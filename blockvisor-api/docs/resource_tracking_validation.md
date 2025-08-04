# Resource Tracking Validation

This document describes the database consistency validation utilities for resource tracking in the Blockvisor API.

## Overview

The resource tracking validation utilities help ensure that the database maintains consistency between:

1. **Node resource fields** (`cpu_cores`, `memory_bytes`, `disk_bytes`) and their corresponding image configurations
2. **Host resource counters** (`node_cpu_cores`, `node_memory_bytes`, `node_disk_bytes`) and the actual sum of node allocations on each host

These utilities are essential for maintaining accurate resource availability calculations and preventing deployment issues caused by inconsistent resource tracking.

## Problem Statement

During node upgrades, if the new image has different resource requirements than the old image, the system should:

1. Update the node's resource allocation fields to match the new image configuration
2. Update the host's resource counter fields to reflect the change in total allocated resources

If these updates fail or are incomplete, the database can become inconsistent, leading to:

- Incorrect resource availability calculations
- Failed node deployments due to perceived resource shortages
- Resource over-allocation or under-allocation

## Validation Utilities

### Core Functions

#### `validate_node_resource_consistency(conn: &mut Conn<'_>) -> Result<Vec<NodeResourceInconsistency>, ValidationError>`

Validates that each node's stored resource fields match the resource requirements defined in its configuration.

**Returns:** A list of inconsistencies where the stored values don't match the config values.

#### `validate_host_counter_consistency(conn: &mut Conn<'_>) -> Result<Vec<HostCounterInconsistency>, ValidationError>`

Validates that each host's resource counter fields match the sum of resource allocations from all nodes on that host.

**Returns:** A list of inconsistencies where the stored counters don't match the actual totals.

#### `validate_resource_tracking_consistency(conn: &mut Conn<'_>) -> Result<ValidationResults, ValidationError>`

Performs comprehensive validation of both node resource fields and host resource counters.

**Returns:** A complete validation report with all inconsistencies found.

### Repair Functions

#### `repair_node_resource_inconsistencies(inconsistencies: &[NodeResourceInconsistency], conn: &mut Conn<'_>) -> Result<usize, ValidationError>`

Repairs node resource field inconsistencies by updating the stored values to match their configurations.

**Returns:** The number of nodes successfully repaired.

#### `repair_host_counter_inconsistencies(inconsistencies: &[HostCounterInconsistency], conn: &mut Conn<'_>) -> Result<usize, ValidationError>`

Repairs host counter inconsistencies by recalculating the counters from actual node allocations.

**Returns:** The number of hosts successfully repaired.

#### `repair_all_resource_inconsistencies(conn: &mut Conn<'_>) -> Result<(usize, usize), ValidationError>`

Performs comprehensive repair of all resource tracking inconsistencies.

**Returns:** A tuple of (nodes_repaired, hosts_repaired).

## Command Line Tool

### `resource-validator` Binary

A command-line utility for validating and repairing resource tracking inconsistencies.

#### Usage

```bash
# Validate resource tracking consistency (read-only)
cargo run --bin resource-validator validate

# Perform dry-run repair (shows what would be fixed)
cargo run --bin resource-validator repair

# Actually perform repairs
cargo run --bin resource-validator repair --apply
```

#### Examples

**Validation Only:**
```bash
$ cargo run --bin resource-validator validate
✅ All resource tracking is consistent!
Checked 150 nodes and 25 hosts - no inconsistencies found.
```

**Dry Run Repair:**
```bash
$ cargo run --bin resource-validator repair
=== DRY RUN RESULTS ===
Would repair:
  3 node resource inconsistencies
  1 host counter inconsistencies

To actually apply these repairs, run:
  resource-validator repair --apply
```

**Apply Repairs:**
```bash
$ cargo run --bin resource-validator repair --apply
=== REPAIR RESULTS ===
Successfully repaired:
  3 node resource inconsistencies
  1 host counter inconsistencies

✅ Resource tracking inconsistencies have been fixed!
```

## SQL Repair Script

For manual database repairs, use the provided SQL script:

```bash
psql -d your_database -f blockvisor-api/scripts/repair_resource_tracking.sql
```

The script performs the following operations:

1. **Updates node resource fields** to match their configurations
2. **Updates host resource counters** to match actual node allocations
3. **Validates the repairs** by checking for remaining inconsistencies
4. **Provides a summary** of the database state after repair

### Script Features

- **Transactional:** All operations are wrapped in a transaction for safety
- **Logging:** Reports the number of nodes and hosts updated
- **Validation:** Includes queries to verify repairs were successful
- **Detailed reporting:** Optional queries to show what was repaired

## Integration with Node Upgrades

The validation utilities are designed to work alongside the enhanced node upgrade functionality. When a node is upgraded:

1. The upgrade process should update both node resource fields and host counters
2. If the upgrade fails, the validation utilities can detect and repair any inconsistencies
3. Regular validation runs can catch any issues that slip through

## Best Practices

### Regular Validation

Run validation checks regularly to catch inconsistencies early:

```bash
# Add to cron job or monitoring system
cargo run --bin resource-validator validate
```

### Pre-Deployment Validation

Always validate resource tracking before major deployments:

```bash
# Validate before deployment
cargo run --bin resource-validator validate
if [ $? -ne 0 ]; then
    echo "Resource tracking inconsistencies found - fixing..."
    cargo run --bin resource-validator repair --apply
fi
```

### Monitoring Integration

Integrate validation results into your monitoring system:

```rust
use blockvisor_api::database::validation::validate_resource_tracking_consistency;

// In your monitoring code
let results = validate_resource_tracking_consistency(&mut conn).await?;
if results.has_inconsistencies() {
    // Alert monitoring system
    alert_inconsistencies_found(results);
}
```

### Database Maintenance

Include resource tracking validation in regular database maintenance:

1. **Weekly validation:** Check for inconsistencies
2. **Monthly repair:** Fix any found inconsistencies
3. **Quarterly audit:** Review validation logs for patterns

## Error Handling

The validation utilities provide detailed error information:

```rust
match validate_resource_tracking_consistency(&mut conn).await {
    Ok(results) => {
        if results.has_inconsistencies() {
            // Handle inconsistencies
            results.log_summary(); // Logs detailed information
        }
    }
    Err(ValidationError::QueryNodes(err)) => {
        // Handle database query errors
    }
    Err(ValidationError::ParseNodeConfig(err)) => {
        // Handle config parsing errors
    }
    // ... other error types
}
```

## Testing

The validation utilities include comprehensive tests:

```bash
# Run validation tests
cargo test database::validation::tests

# Run specific test
cargo test database::validation::tests::test_validate_node_resource_consistency
```

## Troubleshooting

### Common Issues

1. **Config parsing errors:** Usually indicate corrupted node configurations
2. **Database query errors:** May indicate connectivity or permission issues
3. **Integer overflow errors:** Can occur with extremely large resource values

### Debugging

Enable detailed logging to debug validation issues:

```bash
RUST_LOG=debug cargo run --bin resource-validator validate
```

### Recovery

If validation utilities fail, you can use the SQL repair script as a fallback:

```sql
-- Manual validation query
SELECT 
    n.id,
    n.node_name,
    n.cpu_cores as stored_cpu,
    CAST((c.config::jsonb->'vm'->>'cpu_cores')::text AS bigint) as config_cpu
FROM nodes n
INNER JOIN configs c ON n.config_id = c.id
WHERE n.deleted_at IS NULL
AND n.cpu_cores != CAST((c.config::jsonb->'vm'->>'cpu_cores')::text AS bigint);
```

## Performance Considerations

- **Validation** is read-only and safe to run on production systems
- **Repair operations** modify data and should be run during maintenance windows
- **Large databases** may require batched processing for better performance
- **Concurrent operations** are handled safely through database transactions

## Security Considerations

- **Database permissions:** Validation requires read access, repair requires write access
- **Transaction safety:** All repairs are performed within transactions
- **Audit logging:** All operations are logged for audit purposes
- **Backup recommendations:** Always backup before running repair operations