# Implementation Plan

- [x] 1. Create HTTP parameter structure for host nodes endpoint
  - Add `HostNodesParams` struct to `src/http/handler/host.rs` with proper serde attributes
  - Implement parameter validation and conversion to gRPC request
  - Add support for node_states, next_states, offset, limit, and ip_addresses parameters
  - Include UUID validation for host_id parameter
  - _Requirements: 1.1, 3.1, 3.2, 3.3, 4.2_

- [x] 2. Implement host nodes HTTP handler function
  - Add `list_host_nodes` async function to `src/http/handler/host.rs`
  - Extract host_id from URL path parameter
  - Use `Query<HostNodesParams>` for query parameter parsing
  - Call existing `grpc::node::list` function with host-filtered request
  - Handle parameter validation errors with proper HTTP status codes
  - _Requirements: 1.1, 1.2, 2.1, 4.1, 4.2_

- [x] 3. Add route to host router
  - Add new route `/{id}/nodes` with GET method to host router in `src/http/handler/host.rs`
  - Wire the route to the `list_host_nodes` handler function
  - Ensure route is properly positioned in router configuration
  - _Requirements: 1.1_

- [x] 4. Implement parameter validation and mapping
  - Create `to_grpc_request` method for `HostNodesParams` struct
  - Validate host_id UUID format using existing validation utilities
  - Convert node_states strings to gRPC enum integers
  - Convert next_states strings to gRPC enum integers
  - Validate limit parameter range (1-1000)
  - Map all parameters to `api::NodeServiceListRequest` with host_ids filter
  - _Requirements: 3.4, 4.1, 4.2_

- [x] 5. Add comprehensive unit tests for parameter handling
  - Test `HostNodesParams` deserialization from query strings
  - Test parameter validation for valid and invalid UUIDs
  - Test node_states and next_states enum validation
  - Test limit and offset parameter validation
  - Test mapping from HTTP parameters to gRPC request structure
  - Test error response formatting for validation failures
  - _Requirements: 4.1, 4.2_

- [x] 6. Add integration tests for host nodes endpoint
  - Test full HTTP request/response cycle with authentication
  - Test endpoint returns correct node data for host with nodes
  - Test endpoint returns empty array for host with no nodes
  - Test filtering by node_states parameter
  - Test pagination with offset and limit parameters
  - Test authorization checks for different user permission levels
  - Test error responses for invalid host IDs and parameters
  - _Requirements: 1.1, 1.2, 2.1, 2.2, 3.1, 3.2, 3.3, 4.3, 5.1, 5.2, 5.3, 5.4_

- [x] 7. Update OpenAPI specification
  - Add `/v1/host/{id}/nodes` endpoint definition to `openapi.yaml`
  - Document all query parameters with proper types and examples
  - Define response schema referencing existing Node schema
  - Add error response examples for validation and authorization errors
  - Include authentication requirements and permission documentation
  - _Requirements: 1.1, 2.1, 3.1, 3.2, 3.3, 4.1, 4.2_

- [x] 8. Add error handling and response consistency
  - Ensure error responses follow existing API patterns
  - Test that node data structure matches `/v1/node/{id}` endpoint
  - Verify authorization behavior matches existing node endpoints
  - Test edge cases like non-existent hosts and permission boundaries
  - _Requirements: 2.2, 2.3, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4_