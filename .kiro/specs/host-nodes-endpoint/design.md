# Design Document

## Overview

This feature adds a new REST API endpoint `/v1/host/{id}/nodes` that returns all nodes running on a specific host. The endpoint will leverage the existing node listing infrastructure but with host-specific filtering. The implementation will reuse the existing gRPC `NodeServiceListRequest` with the `host_ids` filter set to the specific host ID, ensuring consistency with the existing node data structure and authorization patterns.

## Architecture

### Current Architecture
```
/v1/node → NodeListParams → NodeServiceListRequest → grpc::node::list → NodeFilter → Database Query
/v1/host/{id} → HostServiceGetRequest → grpc::host::get_host → Database Query
```

### New Architecture (Addition)
```
/v1/host/{id}/nodes → HostNodesParams → NodeServiceListRequest → grpc::node::list → NodeFilter → Database Query
```

The new endpoint will:
1. Extract the host ID from the URL path
2. Create a `NodeServiceListRequest` with `host_ids` filter set to the specific host
3. Apply additional query parameter filters (node_states, limit, offset, etc.)
4. Use the existing `grpc::node::list` function for consistent data retrieval and authorization
5. Return the same node data structure as `/v1/node/{id}`

## Components and Interfaces

### 1. HTTP Handler Addition

Add a new route to the host router in `src/http/handler/host.rs`:

```rust
.route("/{id}/nodes", routing::get(list_host_nodes))
```

### 2. HTTP Parameter Structure

Create a dedicated parameter struct for the host nodes endpoint:

```rust
/// HTTP query parameters for listing nodes on a specific host
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNodesParams {
    /// Node states to filter by
    pub node_states: Option<CommaSeparatedList<String>>,
    /// Next states to filter by  
    pub next_states: Option<CommaSeparatedList<String>>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Maximum number of results to return
    pub limit: Option<u64>,
    /// IP addresses to filter by
    pub ip_addresses: Option<CommaSeparatedList<String>>,
}
```

### 3. Handler Implementation

```rust
async fn list_host_nodes(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Path((host_id,)): Path<(String,)>,
    Query(params): Query<HostNodesParams>,
) -> Result<Json<api::NodeServiceListResponse>, Error> {
    // Validate host_id format
    let req = match params.to_grpc_request(host_id) {
        Ok(req) => req,
        Err(validation_error) => {
            return Err(Error::new(
                validation_error.to_json(),
                hyper::StatusCode::BAD_REQUEST,
            ));
        }
    };
    
    // Use existing node list gRPC service
    ctx.read(|read| grpc::node::list(req, headers.into(), read).scope_boxed())
        .await
}
```

### 4. Parameter Mapping

```rust
impl HostNodesParams {
    fn to_grpc_request(self, host_id: String) -> Result<api::NodeServiceListRequest, ParameterValidationError> {
        let mut validation_error = ParameterValidationError::new("Invalid query parameters");

        // Validate host_id
        if let Err(e) = validation::validate_uuid(&host_id, "host_id") {
            validation_error.add_error(e.parameter, e.error, e.expected);
        }

        // Validate and convert node_states
        let node_states = if let Some(node_states) = self.node_states {
            // Convert string states to gRPC enum integers
            // (similar to existing NodeListParams implementation)
        } else {
            Vec::new()
        };

        // Similar validation for other parameters...

        if !validation_error.is_empty() {
            return Err(validation_error);
        }

        Ok(api::NodeServiceListRequest {
            org_ids: Vec::new(), // Let authorization handle org filtering
            host_ids: vec![host_id], // Filter by specific host
            offset: self.offset.unwrap_or(0),
            limit: self.limit.unwrap_or(50),
            node_states,
            next_states,
            ip_addresses: self.ip_addresses.map(|i| i.0).unwrap_or_default(),
            // Set other fields to defaults
            protocol_ids: Vec::new(),
            semantic_versions: Vec::new(),
            user_ids: Vec::new(),
            search: None,
            sort: Vec::new(),
            version_keys: Vec::new(),
        })
    }
}
```

## Data Models

### Request Parameters
- **host_id** (path): UUID of the host to list nodes for
- **node_states** (query): Optional comma-separated list of node states to filter by
- **next_states** (query): Optional comma-separated list of next states to filter by  
- **offset** (query): Number of results to skip (default: 0)
- **limit** (query): Maximum results to return (default: 50, max: 1000)
- **ip_addresses** (query): Optional comma-separated list of IP addresses to filter by

### Response Structure
The response will be identical to the existing `NodeServiceListResponse`:

```json
{
  "nodes": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "org_id": "550e8400-e29b-41d4-a716-446655440000", 
      "host_id": "550e8400-e29b-41d4-a716-446655440000",
      "protocol_id": "bitcoin",
      "state": "running",
      "ip_address": "192.168.1.100",
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z"
      // ... all other node fields
    }
  ],
  "total": 42
}
```

## Error Handling

### Parameter Validation
- **Invalid host_id UUID**: HTTP 400 with detailed UUID validation error
- **Invalid query parameters**: HTTP 400 with parameter-specific validation errors
- **Out of range limit**: HTTP 400 with range validation error

### Authorization Errors
- **No authentication**: HTTP 401 unauthorized
- **Invalid authentication**: HTTP 401 unauthorized  
- **No permission to view host**: HTTP 403 forbidden

### Resource Errors
- **Host not found**: The endpoint will return an empty nodes array with total=0, following REST conventions for sub-resources
- **Database errors**: HTTP 500 internal server error

### Example Error Response
```json
{
  "error": "Invalid query parameters",
  "details": [
    {
      "parameter": "host_id",
      "error": "Invalid UUID format: 'not-a-uuid'",
      "expected": "Valid UUID string (e.g., '550e8400-e29b-41d4-a716-446655440000')"
    },
    {
      "parameter": "node_states", 
      "error": "Invalid value: 'invalid_state'",
      "expected": "One of: starting, running, stopped, failed, upgrading, deleting, deleted"
    }
  ]
}
```

## Testing Strategy

### Unit Tests
- Parameter deserialization for various query parameter combinations
- Parameter validation for invalid UUIDs, states, and ranges
- Mapping from HTTP parameters to gRPC request structure
- Error response formatting

### Integration Tests
- Full HTTP request/response cycle with authentication
- Authorization checks for different user permissions
- Host with no nodes returns empty array
- Host with multiple nodes returns correct data
- Filtering by node states, pagination, etc.
- Error cases: invalid host ID, unauthorized access

### Test Cases
1. **Basic functionality**: Get all nodes for a host
2. **Empty results**: Host with no nodes
3. **Filtering**: Filter by node states, IP addresses
4. **Pagination**: Test offset/limit parameters
5. **Authorization**: Different user permission levels
6. **Validation**: Invalid parameters, malformed UUIDs
7. **Consistency**: Compare data with individual node endpoints

## Implementation Plan

### Phase 1: Core Implementation
1. Add route to host router
2. Create `HostNodesParams` struct with validation
3. Implement `list_host_nodes` handler function
4. Add parameter mapping to `NodeServiceListRequest`

### Phase 2: Testing and Validation
1. Add comprehensive unit tests
2. Add integration tests
3. Test authorization and error handling
4. Validate response consistency with existing endpoints

### Phase 3: Documentation
1. Update OpenAPI specification
2. Add endpoint documentation
3. Update API usage examples

## Authorization and Security

The endpoint will leverage the existing node authorization system:

1. **Authentication**: Requires valid JWT token (same as other endpoints)
2. **Authorization**: Uses existing `NodePerm::List` and `NodeAdminPerm::List` permissions
3. **Org-based filtering**: The gRPC service will automatically filter nodes based on user's org permissions
4. **Host access**: If user can't access the host, they won't see any nodes (empty result)

This ensures that users only see nodes they have permission to view, maintaining the existing security model.

## Performance Considerations

1. **Database Query**: Reuses existing optimized node listing queries with host_id filter
2. **Authorization**: Leverages existing auth caching and permission checks
3. **Response Size**: Pagination limits response size (default 50, max 1000 nodes)
4. **Indexing**: Existing database indexes on host_id will optimize the query

The performance impact should be minimal since it reuses existing, optimized code paths.