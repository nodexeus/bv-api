# Design Document

## Overview

The current REST API implementation attempts to deserialize HTTP query parameters directly into gRPC protobuf message structures using Axum's `Query` extractor and serde. This approach fails because:

1. Protobuf-generated structs (from `tonic::include_proto!`) don't have appropriate serde implementations for query string deserialization
2. Query string deserializers expect flat key-value pairs but protobuf messages contain complex nested structures and arrays
3. Array parameters in query strings require special handling that protobuf structs don't provide

The solution is to create dedicated HTTP parameter structures that can properly deserialize query strings, then map these to the appropriate gRPC request structures.

## Architecture

### Current Architecture (Broken)
```
HTTP Request Query Params → serde Query Deserializer → Protobuf Struct (FAILS)
```

### New Architecture (Fixed)
```
HTTP Request Query Params → serde Query Deserializer → HTTP Param Struct → Mapping Function → Protobuf Struct
```

## Components and Interfaces

### 1. HTTP Parameter Structures

Create dedicated structs for each endpoint that can properly deserialize query parameters:

```rust
// Example for node listing
#[derive(serde::Deserialize)]
pub struct NodeListParams {
    // Support both singular and plural forms
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub search: Option<String>,
    // ... other parameters
}
```

### 2. Custom Serde Types

Implement custom serde types to handle common query parameter patterns:

```rust
// Handle comma-separated values and repeated parameters
pub struct CommaSeparatedList<T>(pub Vec<T>);

// Handle single values that should become arrays
pub struct SingleOrVec<T>(pub Vec<T>);
```

### 3. Mapping Functions

Create explicit mapping functions to convert HTTP parameters to gRPC requests:

```rust
impl From<NodeListParams> for api::NodeServiceListRequest {
    fn from(params: NodeListParams) -> Self {
        Self {
            org_ids: params.org_ids.map(|list| list.0).unwrap_or_default(),
            offset: params.offset.unwrap_or(0),
            limit: params.limit.unwrap_or(50),
            // ... map other fields
        }
    }
}
```

### 4. Updated HTTP Handlers

Modify handlers to use the new parameter structures:

```rust
async fn list(
    State(ctx): State<Arc<Context>>,
    headers: HeaderMap,
    Query(params): Query<NodeListParams>,
) -> Result<Json<api::NodeServiceListResponse>, Error> {
    let req = api::NodeServiceListRequest::from(params);
    ctx.read(|read| grpc::node::list(req, headers.into(), read).scope_boxed())
        .await
}
```

## Data Models

### CommaSeparatedList<T>
- Deserializes comma-separated values: `"a,b,c"` → `vec!["a", "b", "c"]`
- Handles single values: `"a"` → `vec!["a"]`
- Handles repeated parameters: `param=a&param=b` → `vec!["a", "b"]`

### SingleOrVec<T>
- Accepts single values or arrays
- Converts single values to single-item arrays
- Useful for parameters that can be either singular or plural

### Parameter Structures
Each endpoint will have a dedicated parameter struct that:
- Uses appropriate serde attributes for query string deserialization
- Supports both singular and plural parameter names via aliases
- Provides sensible defaults for optional parameters
- Validates parameter types and formats

## Error Handling

### Parameter Validation Errors
- Return HTTP 400 Bad Request for invalid parameters
- Include detailed error messages explaining correct parameter formats
- List valid parameter names when unknown parameters are provided

### Type Conversion Errors
- Handle UUID parsing errors with clear messages
- Validate enum values and provide valid options
- Handle numeric parameter validation

### Example Error Response
```json
{
  "error": "Invalid query parameters",
  "details": [
    {
      "parameter": "org_ids",
      "error": "Invalid UUID format: 'not-a-uuid'",
      "expected": "Valid UUID string or comma-separated list of UUIDs"
    }
  ]
}
```

## Testing Strategy

### Unit Tests
- Test parameter deserialization for each endpoint
- Test mapping functions from HTTP params to gRPC requests
- Test error handling for invalid parameters

### Integration Tests
- Test actual HTTP requests with various parameter combinations
- Test backward compatibility with existing API consumers
- Test error responses for invalid parameters

### Test Cases
1. Single parameter values
2. Multiple parameter values (comma-separated)
3. Multiple parameter values (repeated parameters)
4. Mixed singular/plural parameter names
5. Invalid parameter values
6. Missing required parameters
7. Unknown parameter names

## Implementation Plan

### Phase 1: Core Infrastructure
1. Create custom serde types (`CommaSeparatedList`, `SingleOrVec`)
2. Create parameter validation utilities
3. Create error response structures

### Phase 2: Node Endpoint (Proof of Concept)
1. Create `NodeListParams` struct
2. Implement mapping to `NodeServiceListRequest`
3. Update node list handler
4. Add comprehensive tests

### Phase 3: Rollout to All Endpoints
1. Create parameter structs for all GET endpoints
2. Update all handlers to use new parameter structures
3. Add tests for all endpoints
4. Update API documentation

### Phase 4: Enhanced Features
1. Add parameter validation and better error messages
2. Add support for complex query parameters (nested objects)
3. Add OpenAPI schema generation for parameter documentation