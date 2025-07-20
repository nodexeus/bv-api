use serde_urlencoded;

// Import the parameter structures from the handlers
use blockvisor_api::http::params::{CommaSeparatedList, validation};

/// Test parameter deserialization for all endpoint parameter structures
/// This tests the actual serde deserialization without requiring full HTTP setup

#[derive(serde::Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct TestNodeListParams {
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    #[serde(alias = "host_id")]
    pub host_ids: Option<CommaSeparatedList<String>>,
    #[serde(alias = "user_id")]
    pub user_ids: Option<CommaSeparatedList<String>>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub search: Option<String>,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct TestHostListParams {
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    pub bv_versions: Option<CommaSeparatedList<String>>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub search: Option<String>,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct TestUserListParams {
    #[serde(alias = "user_id")]
    pub user_ids: Option<CommaSeparatedList<String>>,
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub search: Option<String>,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct TestOrgListParams {
    pub member_id: Option<String>,
    pub personal: Option<bool>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub search: Option<String>,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct TestProtocolListParams {
    #[serde(alias = "org_id")]
    pub org_ids: Option<CommaSeparatedList<String>>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub search: Option<String>,
}

/// Test node list parameter deserialization
#[test]
fn test_node_list_parameter_deserialization() {
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    let uuid2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    
    // Test 1: Single org_id parameter (singular form)
    let query = format!("org_id={}&limit=10", uuid1);
    let params: TestNodeListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1]);
    assert_eq!(params.limit, Some(10));

    // Test 2: Multiple org_ids parameter (comma-separated)
    let query = format!("org_ids={},{}&limit=20", uuid1, uuid2);
    let params: TestNodeListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1, uuid2]);
    assert_eq!(params.limit, Some(20));

    // Test 3: Mixed singular and plural parameters
    let query = format!("org_id={}&host_ids={},{}&user_id={}", uuid1, uuid1, uuid2, uuid2);
    let params: TestNodeListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1]);
    assert_eq!(params.host_ids.unwrap().0, vec![uuid1, uuid2]);
    assert_eq!(params.user_ids.unwrap().0, vec![uuid2]);

    // Test 4: Default parameters (empty query)
    let query = "";
    let params: TestNodeListParams = serde_urlencoded::from_str(&query).unwrap();
    assert!(params.org_ids.is_none());
    assert!(params.host_ids.is_none());
    assert!(params.user_ids.is_none());
    assert!(params.offset.is_none());
    assert!(params.limit.is_none());
}

/// Test host list parameter deserialization
#[test]
fn test_host_list_parameter_deserialization() {
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    let uuid2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    
    // Test 1: Single org_id parameter (singular form)
    let query = format!("org_id={}&limit=15", uuid1);
    let params: TestHostListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1]);
    assert_eq!(params.limit, Some(15));

    // Test 2: Multiple org_ids with bv_versions
    let query = format!("org_ids={},{}&bv_versions=1.0.0,1.1.0&offset=5", uuid1, uuid2);
    let params: TestHostListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1, uuid2]);
    assert_eq!(params.bv_versions.unwrap().0, vec!["1.0.0", "1.1.0"]);
    assert_eq!(params.offset, Some(5));
}

/// Test user list parameter deserialization
#[test]
fn test_user_list_parameter_deserialization() {
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    let uuid2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    
    // Test 1: Single user_id parameter (singular form)
    let query = format!("user_id={}&limit=25", uuid1);
    let params: TestUserListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.user_ids.unwrap().0, vec![uuid1]);
    assert_eq!(params.limit, Some(25));

    // Test 2: Mixed singular and plural parameters
    let query = format!("user_id={}&org_ids={},{}&offset=10", uuid1, uuid1, uuid2);
    let params: TestUserListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.user_ids.unwrap().0, vec![uuid1]);
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1, uuid2]);
    assert_eq!(params.offset, Some(10));
}

/// Test organization list parameter deserialization
#[test]
fn test_org_list_parameter_deserialization() {
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    
    // Test 1: member_id and personal parameters
    let query = format!("member_id={}&personal=true&limit=30", uuid1);
    let params: TestOrgListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.member_id, Some(uuid1.to_string()));
    assert_eq!(params.personal, Some(true));
    assert_eq!(params.limit, Some(30));

    // Test 2: personal=false
    let query = "personal=false&offset=5";
    let params: TestOrgListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.personal, Some(false));
    assert_eq!(params.offset, Some(5));
}

/// Test protocol list parameter deserialization
#[test]
fn test_protocol_list_parameter_deserialization() {
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    let uuid2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    
    // Test 1: Single org_id parameter (singular form)
    let query = format!("org_id={}&limit=40", uuid1);
    let params: TestProtocolListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1]);
    assert_eq!(params.limit, Some(40));

    // Test 2: Multiple org_ids parameter (comma-separated)
    let query = format!("org_ids={},{}&offset=15", uuid1, uuid2);
    let params: TestProtocolListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1, uuid2]);
    assert_eq!(params.offset, Some(15));
}

/// Test parameter validation across all endpoints
#[test]
fn test_parameter_validation_integration() {
    // Test UUID validation
    let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
    let invalid_uuid = "not-a-uuid";
    
    assert!(validation::validate_uuid(valid_uuid, "test_id").is_ok());
    assert!(validation::validate_uuid(invalid_uuid, "test_id").is_err());
    
    // Test UUID list validation
    let valid_uuids = vec![valid_uuid.to_string(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string()];
    let invalid_uuids = vec![valid_uuid.to_string(), invalid_uuid.to_string()];
    
    assert!(validation::validate_uuid_list(&valid_uuids, "test_ids").is_ok());
    assert!(validation::validate_uuid_list(&invalid_uuids, "test_ids").is_err());
    
    // Test range validation
    assert!(validation::validate_range(50u64, 1u64, 100u64, "limit").is_ok());
    assert!(validation::validate_range(150u64, 1u64, 100u64, "limit").is_err());
    assert!(validation::validate_range(0u64, 1u64, 100u64, "limit").is_err());
}

/// Test comma-separated parameter parsing with whitespace
#[test]
fn test_comma_separated_whitespace_handling() {
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    let uuid2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    let uuid3 = "7ca8c920-aead-22e2-91c5-11d15fe541d9";
    
    // Test various whitespace patterns
    let test_cases = vec![
        // No whitespace
        format!("org_ids={},{},{}", uuid1, uuid2, uuid3),
        // Whitespace after commas
        format!("org_ids={}, {}, {}", uuid1, uuid2, uuid3),
        // Whitespace before and after commas
        format!("org_ids={} , {} , {}", uuid1, uuid2, uuid3),
        // Mixed whitespace
        format!("org_ids={},  {} ,{}", uuid1, uuid2, uuid3),
    ];

    for query in test_cases {
        let params: TestNodeListParams = serde_urlencoded::from_str(&query).unwrap();
        assert_eq!(params.org_ids.unwrap().0, vec![uuid1, uuid2, uuid3]);
    }
}

/// Test unknown parameter rejection (deny_unknown_fields)
#[test]
fn test_unknown_parameter_rejection() {
    // Test that unknown parameters are rejected
    let query = "unknown_param=value&limit=10";
    let result: Result<TestNodeListParams, _> = serde_urlencoded::from_str(query);
    assert!(result.is_err());
    
    // Test that known parameters still work
    let query = "limit=10&offset=5";
    let result: Result<TestNodeListParams, _> = serde_urlencoded::from_str(query);
    assert!(result.is_ok());
    let params = result.unwrap();
    assert_eq!(params.limit, Some(10));
    assert_eq!(params.offset, Some(5));
}

/// Test edge cases and boundary conditions
#[test]
fn test_edge_cases() {
    // Test minimum and maximum values
    let query = "limit=1&offset=0";
    let params: TestNodeListParams = serde_urlencoded::from_str(query).unwrap();
    assert_eq!(params.limit, Some(1));
    assert_eq!(params.offset, Some(0));
    
    let query = "limit=1000&offset=999999";
    let params: TestNodeListParams = serde_urlencoded::from_str(query).unwrap();
    assert_eq!(params.limit, Some(1000));
    assert_eq!(params.offset, Some(999999));
    
    // Test empty comma-separated values (should be filtered out)
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    let query = format!("org_ids={},,,{}", uuid1, uuid1);
    let params: TestNodeListParams = serde_urlencoded::from_str(&query).unwrap();
    assert_eq!(params.org_ids.unwrap().0, vec![uuid1, uuid1]);
}

/// Test backward compatibility scenarios
#[test]
fn test_backward_compatibility() {
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    
    // Test that both singular and plural forms work for the same parameter
    let singular_query = format!("org_id={}", uuid1);
    let plural_query = format!("org_ids={}", uuid1);
    
    let singular_params: TestNodeListParams = serde_urlencoded::from_str(&singular_query).unwrap();
    let plural_params: TestNodeListParams = serde_urlencoded::from_str(&plural_query).unwrap();
    
    // Both should result in the same parsed value
    assert_eq!(singular_params.org_ids.unwrap().0, vec![uuid1]);
    assert_eq!(plural_params.org_ids.unwrap().0, vec![uuid1]);
    
    // Test the same for other parameter types
    let singular_query = format!("host_id={}", uuid1);
    let plural_query = format!("host_ids={}", uuid1);
    
    let singular_params: TestNodeListParams = serde_urlencoded::from_str(&singular_query).unwrap();
    let plural_params: TestNodeListParams = serde_urlencoded::from_str(&plural_query).unwrap();
    
    assert_eq!(singular_params.host_ids.unwrap().0, vec![uuid1]);
    assert_eq!(plural_params.host_ids.unwrap().0, vec![uuid1]);
}

/// Test parameter validation error handling
#[test]
fn test_parameter_validation_errors() {
    use blockvisor_api::http::params::ParameterValidationError;
    
    // Test creating and using validation errors
    let mut error = ParameterValidationError::new("Test validation error");
    error.add_error("param1", "Invalid value", "Expected valid value");
    error.add_error("param2", "Out of range", "Value between 1 and 100");
    
    assert!(!error.is_empty());
    assert_eq!(error.errors.len(), 2);
    
    // Test JSON conversion
    let json = error.to_json();
    assert_eq!(json["error"], "Test validation error");
    assert_eq!(json["details"].as_array().unwrap().len(), 2);
    assert_eq!(json["details"][0]["parameter"], "param1");
    assert_eq!(json["details"][0]["error"], "Invalid value");
    assert_eq!(json["details"][0]["expected"], "Expected valid value");
}