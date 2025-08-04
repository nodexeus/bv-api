# Design Document

## Overview

This design addresses the resource tracking inconsistency that occurs during node upgrades when image versions have different resource requirements. The fix involves modifying the `UpgradeNode::apply` method to properly update both node resource fields and host resource counters during the upgrade process.

## Architecture

### Current Upgrade Flow

The current upgrade process in `UpgradeNode::apply` performs these steps:
1. Retrieve the existing node and its current config
2. Validate that the new image is different from the current image
3. Create a new NodeConfig using the new image
4. Create and store a new Config record
5. Update the node record with new image_id, config_id, and other metadata
6. Create upgrade log entries

### Enhanced Upgrade Flow

The enhanced upgrade process will add resource tracking updates:
1. Retrieve the existing node and its current config
2. **Extract current resource allocation from the existing node**
3. Validate that the new image is different from the current image
4. Create a new NodeConfig using the new image
5. **Extract new resource requirements from the new NodeConfig**
6. Create and store a new Config record
7. **Update the node record with new resource fields AND metadata**
8. **Update the host resource counters with the resource difference**
9. Create upgrade log entries

## Components and Interfaces

### Modified UpgradeNode::apply Method

**Location:** `blockvisor-api/src/model/node/mod.rs`

**Current Signature:**
```rust
pub async fn apply(self, authz: &AuthZ, conn: &mut Conn<'_>) -> Result<Node, Error>
```

**Enhanced Logic:**
```rust
pub async fn apply(self, authz: &AuthZ, conn: &mut Conn<'_>) -> Result<Node, Error> {
    // 1. Get current node and config
    let node = Node::by_id(self.id, conn).await?;
    let config = Config::by_id(node.config_id, conn).await?;
    
    // 2. Extract current resource allocation
    let old_cpu_cores = node.cpu_cores;
    let old_memory_bytes = node.memory_bytes;
    let old_disk_bytes = node.disk_bytes;
    
    // 3. Validate image change
    if self.image.id == config.image_id {
        return Err(Error::UpgradeSameImage);
    }
    
    // 4. Create new config with new image
    let old_config = config.node_config()?;
    let new_config = old_config.upgrade(self.image.clone(), self.org_id, conn).await?;
    
    // 5. Extract new resource requirements
    let new_cpu_cores = i64::try_from(new_config.vm.cpu_cores).map_err(Error::VmCpu)?;
    let new_memory_bytes = i64::try_from(new_config.vm.memory_bytes).map_err(Error::VmMemory)?;
    let new_disk_bytes = i64::try_from(new_config.vm.disk_bytes).map_err(Error::VmDisk)?;
    
    // 6. Store new config
    let new_config_record = NewConfig { /* ... */ }.create(authz, conn).await?;
    
    // 7. Update node with new resource fields
    let updated_node = diesel::update(nodes::table.find(self.id))
        .set((
            nodes::image_id.eq(self.image.id),
            nodes::config_id.eq(new_config_record.id),
            nodes::cpu_cores.eq(new_cpu_cores),
            nodes::memory_bytes.eq(new_memory_bytes),
            nodes::disk_bytes.eq(new_disk_bytes),
            // ... other existing fields
        ))
        .get_result(conn)
        .await?;
    
    // 8. Update host resource counters
    let cpu_diff = new_cpu_cores - old_cpu_cores;
    let memory_diff = new_memory_bytes - old_memory_bytes;
    let disk_diff = new_disk_bytes - old_disk_bytes;
    
    diesel::update(hosts::table.find(node.host_id))
        .set((
            hosts::node_cpu_cores.eq(hosts::node_cpu_cores + cpu_diff),
            hosts::node_memory_bytes.eq(hosts::node_memory_bytes + memory_diff),
            hosts::node_disk_bytes.eq(hosts::node_disk_bytes + disk_diff),
        ))
        .get_result::<Host>(conn)
        .await?;
    
    // 9. Create log entries (existing logic)
    // ...
    
    Ok(updated_node)
}
```

### Error Handling Enhancements

**New Error Types:**
```rust
pub enum Error {
    // ... existing errors
    /// Failed to convert VM CPU cores: {0}
    VmCpu(std::num::TryFromIntError),
    /// Failed to convert VM memory bytes: {0}
    VmMemory(std::num::TryFromIntError),
    /// Failed to convert VM disk bytes: {0}
    VmDisk(std::num::TryFromIntError),
    /// Failed to update host resource counters: {0}
    UpdateHostCounters(diesel::result::Error),
}
```

### Database Schema Impact

**No schema changes required.** The fix uses existing fields:

**Node Table Fields:**
- `cpu_cores` (bigint) - Will be updated during upgrade
- `memory_bytes` (bigint) - Will be updated during upgrade  
- `disk_bytes` (bigint) - Will be updated during upgrade

**Host Table Fields:**
- `node_cpu_cores` (bigint) - Will be updated with resource difference
- `node_memory_bytes` (bigint) - Will be updated with resource difference
- `node_disk_bytes` (bigint) - Will be updated with resource difference

## Data Models

### Resource Tracking State

**Before Upgrade:**
```
Node: { cpu_cores: 32, memory_bytes: 64GB, disk_bytes: 1TB }
Host: { node_cpu_cores: 32, node_memory_bytes: 64GB, node_disk_bytes: 1TB }
NodeConfig: { vm: { cpu_cores: 32, memory_bytes: 64GB, disk_bytes: 1TB } }
```

**After Upgrade (Current Broken Behavior):**
```
Node: { cpu_cores: 32, memory_bytes: 64GB, disk_bytes: 1TB }  // ❌ Not updated
Host: { node_cpu_cores: 32, node_memory_bytes: 64GB, node_disk_bytes: 1TB }  // ❌ Not updated
NodeConfig: { vm: { cpu_cores: 12, memory_bytes: 32GB, disk_bytes: 500GB } }  // ✅ Updated
```

**After Upgrade (Fixed Behavior):**
```
Node: { cpu_cores: 12, memory_bytes: 32GB, disk_bytes: 500GB }  // ✅ Updated
Host: { node_cpu_cores: 12, node_memory_bytes: 32GB, node_disk_bytes: 500GB }  // ✅ Updated
NodeConfig: { vm: { cpu_cores: 12, memory_bytes: 32GB, disk_bytes: 500GB } }  // ✅ Updated
```

## Error Handling

### Transaction Rollback Strategy

All database operations will be performed within the existing transaction context provided by `WriteConn`. If any step fails:

1. **Resource calculation errors** → Abort before any database changes
2. **Config creation errors** → Abort before node/host updates
3. **Node update errors** → Abort before host counter updates
4. **Host counter update errors** → Transaction rollback restores all previous state

### Validation Checks

**Pre-upgrade Validation:**
- Verify node exists and is not deleted
- Verify new image exists and is accessible
- Verify new image differs from current image
- Verify new config can be created successfully

**Resource Calculation Validation:**
- Verify resource values can be converted to i64 without overflow
- Verify host counter updates won't result in negative values
- Verify resource differences are within reasonable bounds

### Error Recovery

**Graceful Degradation:**
- If resource tracking update fails, the upgrade is aborted entirely
- No partial state is left in the database
- Clear error messages indicate the specific failure point
- Existing node continues to function with original configuration

## Testing Strategy

### Unit Tests

**Test Cases for UpgradeNode::apply:**
1. **Successful upgrade with resource changes** - Verify all fields updated correctly
2. **Successful upgrade with no resource changes** - Verify fields still updated for consistency
3. **Upgrade with same image** - Verify existing error handling still works
4. **Resource calculation overflow** - Verify graceful error handling
5. **Host counter update failure** - Verify transaction rollback
6. **Config creation failure** - Verify no partial updates occur

### Integration Tests

**Test Scenarios:**
1. **End-to-end upgrade flow** - Create node, upgrade image, verify resource tracking
2. **Multiple node upgrades** - Verify host counters accumulate correctly
3. **Concurrent upgrades** - Verify transaction isolation prevents race conditions
4. **Upgrade rollback scenarios** - Verify failed upgrades leave system in consistent state

### Database Consistency Tests

**Validation Queries:**
```sql
-- Verify node resource fields match config
SELECT n.id, n.cpu_cores, c.config 
FROM nodes n 
JOIN configs c ON n.config_id = c.id 
WHERE n.deleted_at IS NULL;

-- Verify host counters match sum of node allocations
SELECT h.id, h.node_cpu_cores, SUM(n.cpu_cores) as actual_total
FROM hosts h 
LEFT JOIN nodes n ON h.id = n.host_id AND n.deleted_at IS NULL
GROUP BY h.id, h.node_cpu_cores
HAVING h.node_cpu_cores != COALESCE(SUM(n.cpu_cores), 0);
```

## Performance Considerations

### Database Impact

**Additional Queries per Upgrade:**
- 1 additional UPDATE on nodes table (adds 3 fields to existing update)
- 1 additional UPDATE on hosts table (new query)
- No additional SELECT queries (reuses existing data)

**Query Performance:**
- Node update: Minimal impact (same WHERE clause, 3 additional SET clauses)
- Host update: Single row update by primary key (very fast)
- No additional indexes required

### Memory Impact

**Additional Memory Usage:**
- 3 additional i64 variables for old resource values
- 3 additional i64 variables for new resource values  
- 3 additional i64 variables for resource differences
- Total: ~72 bytes per upgrade operation

### Concurrency Impact

**Transaction Duration:**
- Minimal increase in transaction time (2 additional simple UPDATEs)
- No additional lock contention (same tables already locked)
- No deadlock risk (same lock acquisition order)

## Migration Strategy

### Deployment Approach

**Zero-Downtime Deployment:**
1. Deploy code changes (backward compatible)
2. No database migrations required
3. Existing upgrade operations continue to work
4. New upgrade operations automatically use enhanced logic

### Data Consistency Repair

**Optional Repair Script:**
A separate utility can be created to fix existing inconsistencies:

```sql
-- Repair script to fix existing resource tracking inconsistencies
UPDATE hosts SET 
    node_cpu_cores = (
        SELECT COALESCE(SUM(n.cpu_cores), 0) 
        FROM nodes n 
        WHERE n.host_id = hosts.id AND n.deleted_at IS NULL
    ),
    node_memory_bytes = (
        SELECT COALESCE(SUM(n.memory_bytes), 0) 
        FROM nodes n 
        WHERE n.host_id = hosts.id AND n.deleted_at IS NULL
    ),
    node_disk_bytes = (
        SELECT COALESCE(SUM(n.disk_bytes), 0) 
        FROM nodes n 
        WHERE n.host_id = hosts.id AND n.deleted_at IS NULL
    );
```

### Rollback Plan

**If Issues Arise:**
1. Revert to previous code version
2. No database rollback needed (schema unchanged)
3. Existing inconsistencies remain but no new ones created
4. System continues to function as before