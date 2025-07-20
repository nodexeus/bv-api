# Implementation Plan

- [x] 1. Create core HTTP parameter utilities
  - Create `src/http/params.rs` module with custom serde types for query parameter handling
  - Implement `CommaSeparatedList<T>` type that handles comma-separated values and repeated parameters
  - Implement `SingleOrVec<T>` type that accepts single values or arrays
  - Write unit tests for custom serde types
  - _Requirements: 1.2, 1.3, 5.1, 5.2, 5.3_

- [x] 2. Create parameter validation and error handling
  - Add parameter validation utilities to `src/http/params.rs`
  - Create structured error types for parameter validation failures
  - Implement error response formatting that lists all validation errors
  - Write unit tests for validation and error handling
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 3. Implement node endpoint parameter handling (proof of concept)
  - Create `NodeListParams` struct in `src/http/handler/node.rs` with proper serde attributes
  - Implement `From<NodeListParams>` for `api::NodeServiceListRequest` mapping
  - Update node list handler to use `Query<NodeListParams>` instead of `Query<api::NodeServiceListRequest>`
  - Add support for both singular (`org_id`) and plural (`org_ids`) parameter names using serde aliases
  - _Requirements: 1.1, 2.1, 2.2, 2.3_

- [x] 4. Add comprehensive tests for node endpoint
  - Write integration tests for node list endpoint with various parameter combinations
  - Test single org_id parameter conversion to org_ids array
  - Test comma-separated org_ids parameter parsing
  - Test repeated org_ids parameter parsing
  - Test parameter validation error responses
  - _Requirements: 1.1, 1.2, 1.3, 4.1, 4.2, 4.3_

- [ ] 5. Implement parameter handling for all GET endpoints
- [x] 5.1 Update host endpoints
  - Create `HostListParams` and `HostListRegionsParams` structs
  - Implement mapping functions to gRPC request types
  - Update host handlers to use new parameter structures
  - _Requirements: 2.4, 3.2_

- [x] 5.2 Update user endpoints  
  - Create `UserListParams` struct
  - Implement mapping function to `api::UserServiceListRequest`
  - Update user list handler
  - _Requirements: 2.4, 3.2_

- [x] 5.3 Update organization endpoints
  - Create `OrgListParams` and `OrgGetProvisionTokenParams` structs
  - Implement mapping functions to gRPC request types
  - Update org handlers
  - _Requirements: 2.4, 3.2_

- [x] 5.4 Update protocol endpoints
  - Create parameter structs for all protocol GET endpoints (`ProtocolGetLatestParams`, `ProtocolGetPricingParams`, etc.)
  - Implement mapping functions to gRPC request types
  - Update all protocol handlers
  - _Requirements: 2.4, 3.2_

- [x] 5.5 Update remaining endpoints
  - Create parameter structs for api_key, archive, bundle, discovery, and invitation endpoints
  - Implement mapping functions for all remaining GET endpoints
  - Update all remaining handlers to use new parameter structures
  - _Requirements: 2.4, 3.2_

- [x] 6. Add integration tests for all endpoints
  - Write integration tests for each updated endpoint
  - Test parameter parsing, validation, and error handling for all endpoints
  - Verify backward compatibility with existing parameter formats
  - Test edge cases and error conditions
  - _Requirements: 1.4, 4.1, 4.2, 4.3, 4.4_

- [x] 7. Enhance error messages and validation
  - Improve parameter validation error messages with specific examples
  - Add validation for UUID format in ID parameters
  - Add validation for enum values with lists of valid options
  - Implement comprehensive parameter validation across all endpoints
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 8. Update HTTP response module for better error handling
  - Enhance `src/http/response.rs` to handle parameter validation errors
  - Ensure consistent error response format across all endpoints
  - Add helper functions for creating parameter validation error responses
  - _Requirements: 4.1, 4.2, 4.3, 4.4_