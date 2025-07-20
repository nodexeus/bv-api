# Requirements Document

## Introduction

The Blockvisor API has a critical issue where REST API endpoints cannot deserialize query parameters at all. The system is attempting to deserialize HTTP query parameters directly into gRPC protobuf message structures using serde, but this fails because query string deserializers cannot handle the complex nested structures and array types expected by protobuf messages. Even when using the correct parameter names (like `org_ids`), the deserializer fails with "expected a sequence" errors because it receives strings but expects arrays.

## Requirements

### Requirement 1

**User Story:** As an API consumer, I want REST API endpoints to successfully deserialize query parameters, so that I can make basic API calls without encountering serialization errors.

#### Acceptance Criteria

1. WHEN I make a GET request to `/v1/node?org_ids=<uuid>&limit=10` THEN the system SHALL successfully deserialize the query parameters
2. WHEN I provide array parameters using repeated query parameters (e.g., `org_ids=id1&org_ids=id2`) THEN the system SHALL parse them into an array
3. WHEN I provide array parameters using comma-separated values (e.g., `org_ids=id1,id2`) THEN the system SHALL parse them into an array  
4. WHEN query parameter deserialization fails THEN the system SHALL return a clear error message explaining the issue

### Requirement 2

**User Story:** As an API consumer, I want to use intuitive parameter names that match common REST API patterns, so that I can easily understand how to call the API.

#### Acceptance Criteria

1. WHEN I use singular parameter names (e.g., `org_id`, `host_id`, `user_id`) for single values THEN the system SHALL accept them and convert to the appropriate gRPC format
2. WHEN I use plural parameter names (e.g., `org_ids`, `host_ids`, `user_ids`) THEN the system SHALL handle them as arrays
3. WHEN I provide a single value to a plural parameter THEN the system SHALL treat it as a single-item array
4. WHEN the API accepts both singular and plural forms THEN it SHALL maintain backward compatibility

### Requirement 3

**User Story:** As a developer maintaining the API, I want a clean separation between HTTP parameter handling and gRPC message structures, so that changes to protobuf definitions don't break REST API usability.

#### Acceptance Criteria

1. WHEN HTTP requests are received THEN the system SHALL use dedicated HTTP parameter structures for deserialization
2. WHEN converting HTTP parameters to gRPC requests THEN the system SHALL use explicit mapping functions
3. WHEN protobuf message structures change THEN the HTTP parameter structures SHALL remain stable for API consumers
4. WHEN new query parameters are added THEN they SHALL follow consistent naming conventions

### Requirement 4

**User Story:** As an API consumer, I want helpful error messages when I provide incorrect parameters, so that I can quickly understand and fix my API calls.

#### Acceptance Criteria

1. WHEN I provide an invalid parameter name THEN the system SHALL return an error listing valid parameter names
2. WHEN I provide an invalid parameter format THEN the system SHALL return an error with examples of correct formats
3. WHEN parameter validation fails THEN the error message SHALL include the specific parameter that failed and why
4. WHEN multiple parameters are invalid THEN the system SHALL return errors for all invalid parameters, not just the first one

### Requirement 5

**User Story:** As an API consumer, I want to use standard REST API conventions for array parameters, so that the API behaves like other REST APIs I'm familiar with.

#### Acceptance Criteria

1. WHEN I need to pass multiple values for a parameter THEN I SHALL be able to use comma-separated values (e.g., `org_ids=id1,id2,id3`)
2. WHEN I need to pass multiple values for a parameter THEN I SHALL be able to use repeated parameters (e.g., `org_ids=id1&org_ids=id2&org_ids=id3`)
3. WHEN I use either array format THEN the system SHALL parse them correctly into the underlying gRPC array structure
4. WHEN I mix singular and plural parameter names THEN the system SHALL handle the conversion appropriately