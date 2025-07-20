# Requirements Document

## Introduction

The Blockvisor API currently provides endpoints to get individual host information (`/v1/host/{id}`) and to list all nodes with filtering (`/v1/node`), but there is no convenient way to get all nodes running on a specific host. Users need to make multiple API calls or use complex filtering to achieve this common use case. This feature will add a dedicated endpoint to list all nodes on a given host, returning the same detailed node information as the individual node endpoint.

## Requirements

### Requirement 1

**User Story:** As an API consumer, I want to retrieve all nodes running on a specific host, so that I can monitor and manage all software instances on that host without making multiple API calls.

#### Acceptance Criteria

1. WHEN I make a GET request to `/v1/host/{id}/nodes` THEN the system SHALL return all nodes running on the specified host
2. WHEN the host exists but has no nodes THEN the system SHALL return an empty array with HTTP 200 status
3. WHEN the host does not exist THEN the system SHALL return HTTP 404 with an appropriate error message
4. WHEN I provide an invalid host ID format THEN the system SHALL return HTTP 400 with parameter validation error

### Requirement 2

**User Story:** As an API consumer, I want the host nodes endpoint to return the same detailed node information as the individual node endpoint, so that I have consistent data structure across the API.

#### Acceptance Criteria

1. WHEN I retrieve nodes from `/v1/host/{id}/nodes` THEN each node SHALL contain the same fields as `/v1/node/{id}` response
2. WHEN I compare node data from both endpoints THEN the data structure and field names SHALL be identical
3. WHEN node information is updated THEN both endpoints SHALL reflect the same updated data
4. WHEN a node has associated metadata THEN it SHALL be included in the host nodes response

### Requirement 3

**User Story:** As an API consumer, I want to filter and paginate the nodes on a host, so that I can efficiently work with hosts that have many nodes.

#### Acceptance Criteria

1. WHEN I provide `limit` parameter THEN the system SHALL return at most that many nodes
2. WHEN I provide `offset` parameter THEN the system SHALL skip that many nodes from the beginning
3. WHEN I provide `node_states` parameter THEN the system SHALL only return nodes in those states
4. WHEN I provide multiple filter parameters THEN the system SHALL apply all filters (AND logic)
5. WHEN no pagination parameters are provided THEN the system SHALL use default values (offset=0, limit=50)

### Requirement 4

**User Story:** As an API consumer, I want proper error handling and validation for the host nodes endpoint, so that I can handle edge cases and invalid requests appropriately.

#### Acceptance Criteria

1. WHEN I provide an invalid UUID for host ID THEN the system SHALL return HTTP 400 with UUID validation error
2. WHEN I provide invalid query parameters THEN the system SHALL return HTTP 400 with detailed parameter validation errors
3. WHEN I don't have permission to access the host THEN the system SHALL return HTTP 403 with authorization error
4. WHEN the system encounters an internal error THEN it SHALL return HTTP 500 with appropriate error message

### Requirement 5

**User Story:** As an API consumer, I want the host nodes endpoint to follow the same authentication and authorization patterns as other endpoints, so that security is consistent across the API.

#### Acceptance Criteria

1. WHEN I make a request without authentication THEN the system SHALL return HTTP 401 unauthorized
2. WHEN I make a request with invalid authentication THEN the system SHALL return HTTP 401 unauthorized  
3. WHEN I don't have permission to view the host THEN the system SHALL return HTTP 403 forbidden
4. WHEN I have permission to view the host THEN I SHALL be able to see all nodes on that host that I have permission to view