use blockvisor_api::database::seed::ORG_ID;
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

mod setup;
use setup::TestServer;
use setup::helper::traits::SocketRpc;

/// Test the HTTP host nodes endpoint with various parameter combinations
#[tokio::test]
async fn test_host_nodes_http_basic() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let host_id = test.seed().host1.id;
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);
    
    // Get JWT token for authentication
    let jwt = test.admin_jwt().await;
    
    // Test 1: Basic request - get all nodes on host
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());
    assert!(body.get("total").is_some());
    
    let nodes = body["nodes"].as_array().unwrap();
    let total = body["total"].as_u64().unwrap();
    
    // All returned nodes should belong to the specified host
    for node in nodes {
        assert_eq!(node["host_id"].as_str().unwrap(), host_id.to_string());
    }
    
    // Total should match the number of nodes returned (for small datasets)
    assert_eq!(nodes.len() as u64, total);
}

/// Test host nodes endpoint with filtering parameters
#[tokio::test]
async fn test_host_nodes_http_filtering() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let host_id = test.seed().host1.id;
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);
    let jwt = test.admin_jwt().await;
    
    // Test 1: Filter by node states
    let url = format!("{}?node_states=running,stopped", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());
    
    let nodes = body["nodes"].as_array().unwrap();
    for node in nodes {
        let state = node["state"].as_str().unwrap();
        assert!(state == "running" || state == "stopped");
        assert_eq!(node["host_id"].as_str().unwrap(), host_id.to_string());
    }

    // Test 2: Pagination parameters
    let url = format!("{}?limit=5&offset=0", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    assert!(nodes.len() <= 5);

    // Test 3: Next states filtering
    let url = format!("{}?next_states=stopping,upgrading", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());

    // Test 4: IP address filtering
    let url = format!("{}?ip_addresses=192.168.1.100,10.0.0.1", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());
    
    let nodes = body["nodes"].as_array().unwrap();
    for node in nodes {
        if let Some(ip_address) = node["ip_address"].as_str() {
            assert!(ip_address == "192.168.1.100" || ip_address == "10.0.0.1");
        }
        assert_eq!(node["host_id"].as_str().unwrap(), host_id.to_string());
    }

    // Test 5: Combined filtering (multiple parameters)
    let url = format!("{}?node_states=running&limit=10&offset=0", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    
    // Should respect both state filter and limit
    assert!(nodes.len() <= 10);
    for node in nodes {
        assert_eq!(node["state"].as_str().unwrap(), "running");
        assert_eq!(node["host_id"].as_str().unwrap(), host_id.to_string());
    }
}

/// Test host nodes endpoint with non-existent host
#[tokio::test]
async fn test_host_nodes_nonexistent_host() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let nonexistent_host_id = Uuid::new_v4();
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), nonexistent_host_id);
    let jwt = test.admin_jwt().await;
    
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    // Should return OK with empty results for non-existent host (REST convention)
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    let total = body["total"].as_u64().unwrap();
    
    assert_eq!(nodes.len(), 0);
    assert_eq!(total, 0);
}

/// Test parameter validation errors for host nodes endpoint
#[tokio::test]
async fn test_host_nodes_parameter_validation() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let jwt = test.admin_jwt().await;

    // Test 1: Invalid host UUID format
    let base_url = format!("http://{}/v1/host/not-a-uuid/nodes", test.socket_addr());
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    assert!(body.get("details").is_some());
    
    let details = body["details"].as_array().unwrap();
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"].as_str().unwrap(), "host_id");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid UUID format"));

    // Test 2: Invalid node states
    let host_id = test.seed().host1.id;
    let url = format!("http://{}/v1/host/{}/nodes?node_states=invalid_state", test.socket_addr(), host_id);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    let details = body["details"].as_array().unwrap();
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"].as_str().unwrap(), "node_states");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid value"));

    // Test 3: Limit out of range
    let url = format!("http://{}/v1/host/{}/nodes?limit=2000", test.socket_addr(), host_id);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    let details = body["details"].as_array().unwrap();
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"].as_str().unwrap(), "limit");
    assert!(details[0]["error"].as_str().unwrap().contains("out of range"));

    // Test 4: Invalid next states
    let url = format!("http://{}/v1/host/{}/nodes?next_states=invalid_next_state", test.socket_addr(), host_id);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    let details = body["details"].as_array().unwrap();
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"].as_str().unwrap(), "next_states");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid value"));
}

/// Test authentication and authorization for host nodes endpoint
#[tokio::test]
async fn test_host_nodes_authentication() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let host_id = test.seed().host1.id;
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);

    // Test 1: No authentication token
    let response = client
        .get(&base_url)
        .send()
        .await
        .unwrap();
    
    // No authentication returns 401 Unauthorized as expected
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test 2: Invalid authentication token
    let response = client
        .get(&base_url)
        .header("Authorization", "Bearer invalid-token")
        .send()
        .await
        .unwrap();
    
    // Invalid tokens return 401 Unauthorized as expected
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test 3: Valid authentication token with super user
    let jwt = test.super_jwt().await;
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
}

/// Test authorization with different user permission levels
#[tokio::test]
async fn test_host_nodes_authorization_levels() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let host_id = test.seed().host1.id;
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);

    // Test 1: Admin user should have access
    let admin_jwt = test.admin_jwt().await;
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", admin_jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());

    // Test 2: Member user should have access to their org's hosts
    let member_jwt = test.member_jwt().await;
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", member_jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());

    // Test 3: Super user should have access
    let super_jwt = test.super_jwt().await;
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", super_jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());

    // Test 4: Unknown user (different org) should get empty results or forbidden
    let unknown_jwt = test.unknown_jwt().await;
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", unknown_jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    // Should either be OK with empty results or FORBIDDEN depending on implementation
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::FORBIDDEN);
    
    if response.status() == StatusCode::OK {
        let body: Value = response.json().await.unwrap();
        let nodes = body["nodes"].as_array().unwrap();
        let total = body["total"].as_u64().unwrap();
        // Unknown user should not see nodes from other orgs
        assert_eq!(nodes.len(), 0);
        assert_eq!(total, 0);
    }
}

/// Test data consistency between host nodes endpoint and individual node endpoint
#[tokio::test]
async fn test_host_nodes_data_consistency() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let host_id = test.seed().host1.id;
    let jwt = test.admin_jwt().await;
    
    // Get nodes from host nodes endpoint
    let host_nodes_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);
    let response = client
        .get(&host_nodes_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let host_nodes_body: Value = response.json().await.unwrap();
    let nodes = host_nodes_body["nodes"].as_array().unwrap();
    
    if !nodes.is_empty() {
        // Pick the first node and compare with individual node endpoint
        let node = &nodes[0];
        let node_id = node["id"].as_str().unwrap();
        
        let individual_node_url = format!("http://{}/v1/node/{}", test.socket_addr(), node_id);
        let response = client
            .get(&individual_node_url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
        let individual_node_body: Value = response.json().await.unwrap();
        let individual_node = &individual_node_body["node"];
        
        // Compare key fields to ensure consistency
        assert_eq!(node["id"], individual_node["id"]);
        assert_eq!(node["host_id"], individual_node["host_id"]);
        assert_eq!(node["org_id"], individual_node["org_id"]);
        assert_eq!(node["state"], individual_node["state"]);
        assert_eq!(node["protocol_id"], individual_node["protocol_id"]);
        
        // Ensure the node belongs to the correct host
        assert_eq!(node["host_id"].as_str().unwrap(), host_id.to_string());
    }
}

/// Test default parameter values
#[tokio::test]
async fn test_host_nodes_defaults() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let host_id = test.seed().host1.id;
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);
    let jwt = test.admin_jwt().await;
    
    // Request without any query parameters should use defaults
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    
    // Should return at most 50 nodes (default limit)
    assert!(nodes.len() <= 50);
    
    // All nodes should belong to the specified host
    for node in nodes {
        assert_eq!(node["host_id"].as_str().unwrap(), host_id.to_string());
    }
}

/// Test edge cases and comprehensive error handling
#[tokio::test]
async fn test_host_nodes_edge_cases() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let jwt = test.admin_jwt().await;

    // Test 1: Host with no nodes (using host2 which typically has no nodes)
    let host_id = test.seed().host2.id;
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    let total = body["total"].as_u64().unwrap();
    
    // Should return empty array for host with no nodes
    assert_eq!(nodes.len(), 0);
    assert_eq!(total, 0);

    // Test 2: Multiple validation errors in single request
    let host_id = test.seed().host1.id;
    let url = format!(
        "http://{}/v1/host/not-a-uuid/nodes?node_states=invalid_state&limit=2000&next_states=bad_state", 
        test.socket_addr()
    );
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    assert!(body.get("details").is_some());
    
    let details = body["details"].as_array().unwrap();
    assert!(details.len() >= 2); // Should have multiple validation errors

    // Test 3: Boundary values for pagination
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);
    
    // Test minimum valid limit
    let url = format!("{}?limit=1", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test maximum valid limit
    let url = format!("{}?limit=1000", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test zero limit (should fail)
    let url = format!("{}?limit=0", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test 4: Large offset value
    let url = format!("{}?offset=1000000", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    // With large offset, should return empty results
    assert_eq!(nodes.len(), 0);

    // Test 5: Empty parameter values
    let url = format!("{}?node_states=&next_states=", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    // Should handle empty parameters gracefully
    assert_eq!(response.status(), StatusCode::OK);
}

/// Test response format consistency and required fields
#[tokio::test]
async fn test_host_nodes_response_format() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let host_id = test.seed().host1.id;
    let base_url = format!("http://{}/v1/host/{}/nodes", test.socket_addr(), host_id);
    let jwt = test.admin_jwt().await;
    
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    
    // Verify required top-level fields
    assert!(body.get("nodes").is_some(), "Response missing 'nodes' field");
    assert!(body.get("total").is_some(), "Response missing 'total' field");
    
    let nodes = body["nodes"].as_array().unwrap();
    let total = body["total"].as_u64().unwrap();
    
    // Verify total is a valid number
    assert!(total >= 0);
    
    // If nodes exist, verify each node has required fields
    for node in nodes {
        assert!(node.get("id").is_some(), "Node missing 'id' field");
        assert!(node.get("host_id").is_some(), "Node missing 'host_id' field");
        assert!(node.get("org_id").is_some(), "Node missing 'org_id' field");
        assert!(node.get("state").is_some(), "Node missing 'state' field");
        assert!(node.get("protocol_id").is_some(), "Node missing 'protocol_id' field");
        assert!(node.get("created_at").is_some(), "Node missing 'created_at' field");
        assert!(node.get("updated_at").is_some(), "Node missing 'updated_at' field");
        
        // Verify host_id matches the requested host
        assert_eq!(node["host_id"].as_str().unwrap(), host_id.to_string());
        
        // Verify UUID format for id fields
        let node_id = node["id"].as_str().unwrap();
        assert!(Uuid::parse_str(node_id).is_ok(), "Invalid node ID UUID format");
        
        let node_host_id = node["host_id"].as_str().unwrap();
        assert!(Uuid::parse_str(node_host_id).is_ok(), "Invalid host ID UUID format");
        
        let node_org_id = node["org_id"].as_str().unwrap();
        assert!(Uuid::parse_str(node_org_id).is_ok(), "Invalid org ID UUID format");
    }
}