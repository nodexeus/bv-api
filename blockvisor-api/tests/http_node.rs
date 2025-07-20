use blockvisor_api::database::seed::ORG_ID;
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

mod setup;
use setup::TestServer;
use setup::helper::traits::SocketRpc;

/// Test the HTTP node list endpoint with various parameter combinations
#[tokio::test]
async fn test_node_list_http_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/node", test.socket_addr());
    
    // Get JWT token for authentication
    let jwt = test.admin_jwt().await;
    
    // Test 1: Single org_id parameter (singular form)
    let url = format!("{}?org_id={}&limit=10", base_url, ORG_ID);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());
    assert!(body.get("total").is_some());

    // Test 2: Multiple org_ids parameter (comma-separated)
    let org_id2 = Uuid::new_v4();
    let url = format!("{}?org_ids={},{}&limit=20", base_url, ORG_ID, org_id2);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());

    // Test 3: Default parameters (no query params)
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());

    // Test 4: Multiple parameter types
    let host_id = test.seed().host1.id;
    let url = format!(
        "{}?org_id={}&host_ids={}&limit=5&offset=0", 
        base_url, ORG_ID, host_id
    );
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());
}

/// Test parameter validation errors
#[tokio::test]
async fn test_node_list_parameter_validation() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/node", test.socket_addr());
    let jwt = test.admin_jwt().await;

    // Test 1: Invalid UUID format
    let url = format!("{}?org_id=not-a-uuid", base_url);
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
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"], "org_ids");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid UUID format"));

    // Test 2: Limit out of range
    let url = format!("{}?limit=2000", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    
    let details = body["details"].as_array().unwrap();
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"], "limit");
    assert!(details[0]["error"].as_str().unwrap().contains("out of range"));

    // Test 3: Multiple validation errors
    let url = format!("{}?org_id=not-a-uuid&limit=2000", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    
    let details = body["details"].as_array().unwrap();
    assert_eq!(details.len(), 2); // Should have both validation errors
}

/// Test backward compatibility - ensure existing API consumers still work
#[tokio::test]
async fn test_node_list_backward_compatibility() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/node", test.socket_addr());
    let jwt = test.admin_jwt().await;

    // Test that both singular and plural forms work
    let test_cases = vec![
        format!("org_id={}", ORG_ID),
        format!("org_ids={}", ORG_ID),
        format!("host_id={}", test.seed().host1.id),
        format!("host_ids={}", test.seed().host1.id),
        format!("user_id={}", test.seed().admin.id),
        format!("user_ids={}", test.seed().admin.id),
    ];

    for query in test_cases {
        let url = format!("{}?{}", base_url, query);
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(
            response.status(), 
            StatusCode::OK,
            "Failed for query: {}", query
        );
        
        let body: Value = response.json().await.unwrap();
        assert!(body.get("nodes").is_some(), "Missing nodes field for query: {}", query);
        assert!(body.get("total").is_some(), "Missing total field for query: {}", query);
    }
}

/// Test comma-separated parameter parsing
#[tokio::test]
async fn test_node_list_comma_separated_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/node", test.socket_addr());
    let jwt = test.admin_jwt().await;

    // Test comma-separated org_ids
    let org_id2 = Uuid::new_v4();
    let org_id3 = Uuid::new_v4();
    let url = format!("{}?org_ids={},{},{}", base_url, ORG_ID, org_id2, org_id3);
    
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());

    // Test comma-separated with whitespace
    let url = format!("{}?org_ids={}, {}, {}", base_url, ORG_ID, org_id2, org_id3);
    
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("nodes").is_some());
}

/// Test edge cases and boundary conditions
#[tokio::test]
async fn test_node_list_edge_cases() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/node", test.socket_addr());
    let jwt = test.admin_jwt().await;

    // Test minimum limit
    let url = format!("{}?limit=1", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);

    // Test maximum limit
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

    // Test large offset
    let url = format!("{}?offset=1000000", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
}