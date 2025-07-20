use blockvisor_api::database::seed::ORG_ID;
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

mod setup;
use setup::TestServer;
use setup::helper::traits::SocketRpc;

/// Test the HTTP host list endpoint with various parameter combinations
#[tokio::test]
async fn test_host_list_http_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/host", test.socket_addr());
    
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
    assert!(body.get("hosts").is_some());
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
    assert!(body.get("hosts").is_some());

    // Test 3: Default parameters (no query params)
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("hosts").is_some());

    // Test 4: Multiple parameter types with bv_versions
    let url = format!(
        "{}?org_id={}&bv_versions=1.0.0,1.1.0&limit=5&offset=0", 
        base_url, ORG_ID
    );
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("hosts").is_some());
}

/// Test host list parameter validation errors
#[tokio::test]
async fn test_host_list_parameter_validation() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/host", test.socket_addr());
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
}

/// Test the HTTP host regions list endpoint
#[tokio::test]
async fn test_host_regions_list_http_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/host/regions", test.socket_addr());
    let jwt = test.admin_jwt().await;

    // Test 1: Required image_id parameter
    let url = format!("{}?image_id=test-image-123", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("regions").is_some());

    // Test 2: With optional org_id parameter
    let url = format!("{}?image_id=test-image-123&org_id={}", base_url, ORG_ID);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("regions").is_some());

    // Test 3: Invalid org_id format
    let url = format!("{}?image_id=test-image-123&org_id=not-a-uuid", base_url);
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
    assert_eq!(details[0]["parameter"], "org_id");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid UUID format"));
}

/// Test the HTTP user list endpoint with various parameter combinations
#[tokio::test]
async fn test_user_list_http_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/user", test.socket_addr());
    let jwt = test.admin_jwt().await;
    
    // Test 1: Single user_id parameter (singular form)
    let user_id = test.seed().admin.id;
    let url = format!("{}?user_id={}&limit=10", base_url, user_id);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("users").is_some());
    assert!(body.get("total").is_some());

    // Test 2: Multiple user_ids parameter (comma-separated)
    let user_id2 = Uuid::new_v4();
    let url = format!("{}?user_ids={},{}&limit=20", base_url, user_id, user_id2);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("users").is_some());

    // Test 3: Mixed singular and plural parameters
    let url = format!("{}?user_id={}&org_ids={}&limit=15", base_url, user_id, ORG_ID);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("users").is_some());

    // Test 4: Default parameters (no query params)
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("users").is_some());
}

/// Test user list parameter validation errors
#[tokio::test]
async fn test_user_list_parameter_validation() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/user", test.socket_addr());
    let jwt = test.admin_jwt().await;

    // Test 1: Invalid user_id UUID format
    let url = format!("{}?user_id=not-a-uuid", base_url);
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
    assert_eq!(details[0]["parameter"], "user_ids");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid UUID format"));

    // Test 2: Invalid org_id UUID format
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
    
    let details = body["details"].as_array().unwrap();
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"], "org_ids");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid UUID format"));

    // Test 3: Multiple validation errors
    let url = format!("{}?user_id=not-a-uuid&org_id=also-not-a-uuid&limit=2000", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    
    let details = body["details"].as_array().unwrap();
    assert_eq!(details.len(), 3); // Should have all three validation errors
}

/// Test the HTTP organization list endpoint with various parameter combinations
#[tokio::test]
async fn test_org_list_http_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/org", test.socket_addr());
    let jwt = test.admin_jwt().await;
    
    // Test 1: member_id parameter
    let member_id = test.seed().admin.id;
    let url = format!("{}?member_id={}&limit=10", base_url, member_id);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("orgs").is_some());
    assert!(body.get("total").is_some());

    // Test 2: personal parameter
    let url = format!("{}?personal=true&limit=5", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("orgs").is_some());

    // Test 3: Combined parameters
    let url = format!("{}?member_id={}&personal=false&offset=0&limit=25", base_url, member_id);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("orgs").is_some());

    // Test 4: Default parameters (no query params)
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("orgs").is_some());
}

/// Test organization list parameter validation errors
#[tokio::test]
async fn test_org_list_parameter_validation() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/org", test.socket_addr());
    let jwt = test.admin_jwt().await;

    // Test 1: Invalid member_id UUID format
    let url = format!("{}?member_id=not-a-uuid", base_url);
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
    assert_eq!(details[0]["parameter"], "member_id");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid UUID format"));

    // Test 2: Limit out of range
    let url = format!("{}?limit=1500", base_url);
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
}

/// Test the HTTP protocol list endpoint with various parameter combinations
#[tokio::test]
async fn test_protocol_list_http_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/protocol", test.socket_addr());
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
    assert!(body.get("protocols").is_some());
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
    assert!(body.get("protocols").is_some());

    // Test 3: Default parameters (no query params)
    let response = client
        .get(&base_url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("protocols").is_some());

    // Test 4: Offset and limit parameters
    let url = format!("{}?offset=5&limit=15", base_url);
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_ref()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("protocols").is_some());
}

/// Test protocol list parameter validation errors
#[tokio::test]
async fn test_protocol_list_parameter_validation() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/v1/protocol", test.socket_addr());
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
    
    let details = body["details"].as_array().unwrap();
    assert!(!details.is_empty());
    assert_eq!(details[0]["parameter"], "org_ids");
    assert!(details[0]["error"].as_str().unwrap().contains("Invalid UUID format"));

    // Test 2: Limit out of range
    let url = format!("{}?limit=1500", base_url);
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
}

/// Test backward compatibility - ensure existing API consumers still work
#[tokio::test]
async fn test_backward_compatibility_all_endpoints() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let jwt = test.admin_jwt().await;
    let base_addr = test.socket_addr();

    // Test cases for different endpoints with both singular and plural forms
    let test_cases = vec![
        // Node endpoint
        (format!("http://{}/v1/node", base_addr), vec![
            format!("org_id={}", ORG_ID),
            format!("org_ids={}", ORG_ID),
            format!("host_id={}", test.seed().host1.id),
            format!("host_ids={}", test.seed().host1.id),
            format!("user_id={}", test.seed().admin.id),
            format!("user_ids={}", test.seed().admin.id),
        ]),
        // Host endpoint
        (format!("http://{}/v1/host", base_addr), vec![
            format!("org_id={}", ORG_ID),
            format!("org_ids={}", ORG_ID),
        ]),
        // User endpoint
        (format!("http://{}/v1/user", base_addr), vec![
            format!("user_id={}", test.seed().admin.id),
            format!("user_ids={}", test.seed().admin.id),
            format!("org_id={}", ORG_ID),
            format!("org_ids={}", ORG_ID),
        ]),
        // Protocol endpoint
        (format!("http://{}/v1/protocol", base_addr), vec![
            format!("org_id={}", ORG_ID),
            format!("org_ids={}", ORG_ID),
        ]),
    ];

    for (base_url, queries) in test_cases {
        for query in queries {
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
                "Failed for URL: {}", url
            );
            
            let body: Value = response.json().await.unwrap();
            // Each endpoint should have some kind of list response
            assert!(
                body.as_object().unwrap().keys().any(|k| k.contains("s") || k == "total"),
                "Missing expected response fields for URL: {}", url
            );
        }
    }
}

/// Test comma-separated parameter parsing across all endpoints
#[tokio::test]
async fn test_comma_separated_parameters_all_endpoints() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let jwt = test.admin_jwt().await;
    let base_addr = test.socket_addr();

    // Test comma-separated parameters for different endpoints
    let org_id2 = Uuid::new_v4();
    let org_id3 = Uuid::new_v4();
    
    let test_cases = vec![
        // Node endpoint with comma-separated org_ids
        format!("http://{}/v1/node?org_ids={},{},{}", base_addr, ORG_ID, org_id2, org_id3),
        // Host endpoint with comma-separated org_ids
        format!("http://{}/v1/host?org_ids={},{},{}", base_addr, ORG_ID, org_id2, org_id3),
        // User endpoint with comma-separated org_ids
        format!("http://{}/v1/user?org_ids={},{},{}", base_addr, ORG_ID, org_id2, org_id3),
        // Protocol endpoint with comma-separated org_ids
        format!("http://{}/v1/protocol?org_ids={},{},{}", base_addr, ORG_ID, org_id2, org_id3),
    ];

    for url in test_cases {
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(
            response.status(), 
            StatusCode::OK,
            "Failed for comma-separated URL: {}", url
        );
        
        let body: Value = response.json().await.unwrap();
        assert!(
            body.as_object().unwrap().keys().any(|k| k.contains("s") || k == "total"),
            "Missing expected response fields for comma-separated URL: {}", url
        );
    }
}

/// Test edge cases and boundary conditions across all endpoints
#[tokio::test]
async fn test_edge_cases_all_endpoints() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let jwt = test.admin_jwt().await;
    let base_addr = test.socket_addr();

    let endpoints = vec![
        format!("http://{}/v1/node", base_addr),
        format!("http://{}/v1/host", base_addr),
        format!("http://{}/v1/user", base_addr),
        format!("http://{}/v1/protocol", base_addr),
        format!("http://{}/v1/org", base_addr),
    ];

    for base_url in endpoints {
        // Test minimum limit
        let url = format!("{}?limit=1", base_url);
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK, "Failed minimum limit for: {}", base_url);

        // Test maximum limit
        let url = format!("{}?limit=1000", base_url);
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK, "Failed maximum limit for: {}", base_url);

        // Test zero limit (should fail)
        let url = format!("{}?limit=0", base_url);
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Zero limit should fail for: {}", base_url);

        // Test over-limit (should fail)
        let url = format!("{}?limit=2000", base_url);
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Over-limit should fail for: {}", base_url);

        // Test large offset
        let url = format!("{}?offset=1000000", base_url);
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK, "Failed large offset for: {}", base_url);
    }
}

/// Test unknown parameter handling (should be rejected due to deny_unknown_fields)
#[tokio::test]
async fn test_unknown_parameters() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let jwt = test.admin_jwt().await;
    let base_addr = test.socket_addr();

    let endpoints = vec![
        format!("http://{}/v1/node", base_addr),
        format!("http://{}/v1/host", base_addr),
        format!("http://{}/v1/user", base_addr),
        format!("http://{}/v1/protocol", base_addr),
        format!("http://{}/v1/org", base_addr),
    ];

    for base_url in endpoints {
        // Test unknown parameter
        let url = format!("{}?unknown_param=value", base_url);
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(
            response.status(), 
            StatusCode::BAD_REQUEST, 
            "Unknown parameter should be rejected for: {}", base_url
        );
    }
}

/// Test whitespace handling in comma-separated values
#[tokio::test]
async fn test_comma_separated_whitespace_handling() {
    let test = TestServer::new().await;
    let client = reqwest::Client::new();
    let jwt = test.admin_jwt().await;
    let base_addr = test.socket_addr();

    let org_id2 = Uuid::new_v4();
    let org_id3 = Uuid::new_v4();
    
    // Test comma-separated with various whitespace patterns
    let test_cases = vec![
        // No whitespace
        format!("http://{}/v1/node?org_ids={},{},{}", base_addr, ORG_ID, org_id2, org_id3),
        // Whitespace after commas
        format!("http://{}/v1/node?org_ids={}, {}, {}", base_addr, ORG_ID, org_id2, org_id3),
        // Whitespace before and after commas
        format!("http://{}/v1/node?org_ids={} , {} , {}", base_addr, ORG_ID, org_id2, org_id3),
    ];

    for url in test_cases {
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt.as_ref()))
            .send()
            .await
            .unwrap();
        
        assert_eq!(
            response.status(), 
            StatusCode::OK,
            "Failed for whitespace test URL: {}", url
        );
        
        let body: Value = response.json().await.unwrap();
        assert!(body.get("nodes").is_some(), "Missing nodes field for URL: {}", url);
    }
}