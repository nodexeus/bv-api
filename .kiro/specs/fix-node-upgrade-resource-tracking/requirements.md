# Requirements Document

## Introduction

When nodes are upgraded to new image versions that have different resource requirements (CPU, memory, disk), the system currently fails to update the resource tracking counters. This causes the host resource counters to become permanently out of sync, leading to incorrect resource availability calculations that prevent new nodes from being deployed even when sufficient resources are actually available.

The system correctly updates the node's configuration to use the new image, but fails to:
1. Update the node's stored resource allocation fields (`cpu_cores`, `memory_bytes`, `disk_bytes`)
2. Update the host's resource counter fields (`node_cpu_cores`, `node_memory_bytes`, `node_disk_bytes`)

This results in resource counters that reflect old resource requirements while the actual deployed nodes use the correct new requirements.

## Requirements

### Requirement 1: Update Node Resource Fields During Upgrade

**User Story:** As a system administrator, I want node upgrade operations to update the node's resource allocation fields so that the database accurately reflects the current resource usage.

#### Acceptance Criteria

1. WHEN a node is upgraded to a new image version THEN the system SHALL calculate the new resource requirements from the new image configuration
2. WHEN the new resource requirements are calculated THEN the system SHALL update the node's `cpu_cores`, `memory_bytes`, and `disk_bytes` fields in the database
3. WHEN the node resource fields are updated THEN the system SHALL ensure the values match the new image's resource requirements exactly
4. IF the resource calculation fails THEN the system SHALL abort the upgrade operation and return an appropriate error

### Requirement 2: Update Host Resource Counters During Upgrade

**User Story:** As a system administrator, I want host resource counters to be updated during node upgrades so that resource availability calculations remain accurate.

#### Acceptance Criteria

1. WHEN a node upgrade begins THEN the system SHALL retrieve the current node's resource allocation values
2. WHEN the new resource requirements are calculated THEN the system SHALL calculate the difference between old and new resource requirements
3. WHEN the node upgrade is applied THEN the system SHALL update the host's resource counters by subtracting the old values and adding the new values
4. WHEN host counters are updated THEN the system SHALL ensure `node_cpu_cores`, `node_memory_bytes`, and `node_disk_bytes` reflect the actual total resources allocated to all nodes on the host
5. IF host counter updates fail THEN the system SHALL abort the upgrade operation and maintain data consistency

### Requirement 3: Maintain Transactional Consistency

**User Story:** As a system administrator, I want node upgrade operations to be atomic so that partial failures don't leave the system in an inconsistent state.

#### Acceptance Criteria

1. WHEN a node upgrade operation begins THEN the system SHALL perform all database updates within a single transaction
2. WHEN any part of the upgrade fails THEN the system SHALL rollback all changes and leave the node in its original state
3. WHEN the upgrade completes successfully THEN the system SHALL ensure all resource tracking fields are consistent with each other
4. WHEN the upgrade transaction commits THEN the system SHALL ensure the node record, host counters, and config records all reflect the new resource requirements

### Requirement 4: Preserve Existing Upgrade Functionality

**User Story:** As a system administrator, I want the existing node upgrade functionality to continue working exactly as before, with only the addition of proper resource tracking.

#### Acceptance Criteria

1. WHEN a node upgrade is performed THEN the system SHALL continue to update all existing fields (image_id, config_id, protocol_id, etc.) as before
2. WHEN upgrade logging occurs THEN the system SHALL continue to create the same log entries as before
3. WHEN upgrade commands are generated THEN the system SHALL continue to create the same command messages as before
4. WHEN upgrade validation occurs THEN the system SHALL continue to perform the same validation checks as before
5. IF the new image has the same resource requirements as the old image THEN the system SHALL still update the resource fields for consistency

### Requirement 5: Handle Edge Cases Gracefully

**User Story:** As a system administrator, I want the system to handle edge cases in resource tracking updates without causing system failures.

#### Acceptance Criteria

1. WHEN a node upgrade involves zero resource changes THEN the system SHALL still update the resource fields to ensure consistency
2. WHEN host resource counters would become negative due to calculation errors THEN the system SHALL prevent negative values and log an error
3. WHEN the old node configuration cannot be retrieved THEN the system SHALL abort the upgrade with a clear error message
4. WHEN the new image configuration is invalid THEN the system SHALL abort the upgrade before making any database changes
5. WHEN resource calculation overflows occur THEN the system SHALL handle the error gracefully and abort the upgrade