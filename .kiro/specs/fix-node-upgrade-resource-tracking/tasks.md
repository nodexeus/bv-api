# Implementation Plan

- [x] 1. Add resource tracking error types to node model

  - Add new error variants for resource conversion and host counter update failures
  - Implement error conversion to gRPC Status codes
  - Add error handling for integer overflow scenarios
  - _Requirements: 1.4, 2.5, 5.5_

- [x] 2. Implement resource extraction and calculation logic

  - Extract current resource values from existing node record
  - Calculate new resource requirements from upgraded NodeConfig
  - Implement safe integer conversion with overflow protection
  - Calculate resource differences for host counter updates
  - _Requirements: 1.1, 1.2, 2.1, 2.2_

- [x] 3. Update UpgradeNode::apply method with resource tracking

  - Modify the upgrade method to extract old resource values before changes
  - Add new resource field updates to the node record update query
  - Implement host resource counter updates using calculated differences
  - Ensure all updates happen within the existing transaction
  - _Requirements: 1.2, 1.3, 2.3, 2.4, 3.1, 3.2_

- [x] 4. Add validation and error handling for edge cases

  - Validate that resource calculations don't cause integer overflow
  - Prevent host resource counters from becoming negative
  - Add validation for invalid image configurations
  - Implement graceful handling when old config cannot be retrieved
  - _Requirements: 1.4, 2.5, 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 5. Preserve existing upgrade functionality

  - Ensure all existing node fields continue to be updated as before
  - Maintain existing upgrade logging behavior
  - Preserve existing command generation logic
  - Keep existing validation checks intact
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 6. Create unit tests for resource tracking logic

  - Test successful upgrade with resource changes
  - Test upgrade with no resource changes (same requirements)
  - Test error handling for resource calculation failures
  - Test host counter update failure scenarios
  - Test transaction rollback on upgrade failures
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3_

- [x] 7. Create integration tests for end-to-end upgrade flow

  - Test complete node upgrade with resource tracking verification
  - Test multiple node upgrades on same host with counter accumulation
  - Test concurrent upgrade scenarios for transaction isolation
  - Test upgrade rollback scenarios for data consistency
  - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4_

- [x] 8. Add database consistency validation utilities

  - Create utility to verify node resource fields match their configs
  - Create utility to verify host counters match sum of node allocations
  - Add logging for resource tracking inconsistencies
  - Create repair script for fixing existing inconsistencies
  - _Requirements: 2.4, 3.3, 5.2_

- [ ] 9. Test upgrade scenarios with different resource changes

  - Test upgrade from high-resource to low-resource image
  - Test upgrade from low-resource to high-resource image
  - Test upgrade with same resource requirements
  - Test upgrade with zero resource requirements
  - Verify host counters are updated correctly in all scenarios
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 2.4, 4.5, 5.1_

- [ ] 10. Validate error handling and transaction consistency
  - Test that upgrade failures leave system in consistent state
  - Verify that partial failures don't corrupt resource tracking
  - Test error messages provide clear indication of failure points
  - Confirm that failed upgrades can be retried successfully
  - _Requirements: 1.4, 2.5, 3.1, 3.2, 3.3, 5.2, 5.3, 5.4, 5.5_
