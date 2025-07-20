use blockvisor_api::http::params::{validation, ParameterValidationError};

#[test]
fn test_comprehensive_parameter_validation() {
    // Test UUID validation with enhanced error messages
    let result = validation::validate_uuid("not-a-uuid", "org_id");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.parameter, "org_id");
    assert!(error.error.contains("Invalid UUID format: 'not-a-uuid'"));
    assert!(error.expected.contains("550e8400-e29b-41d4-a716-446655440000"));
}

#[test]
fn test_uuid_list_validation_with_index_errors() {
    let uuid_list = vec![
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
        "invalid-uuid".to_string(),
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
    ];
    
    let result = validation::validate_uuid_list(&uuid_list, "org_ids");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.error.contains("at index 1"));
    assert!(error.error.contains("invalid-uuid"));
}

#[test]
fn test_node_state_validation() {
    // Test valid node state
    let result = validation::validate_node_state("running", "state");
    assert!(result.is_ok());
    
    // Test invalid node state with helpful error message
    let result = validation::validate_node_state("invalid_state", "state");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.parameter, "state");
    assert!(error.error.contains("Invalid value: 'invalid_state'"));
    assert!(error.expected.contains("starting, running, stopped, failed, upgrading, deleting, deleted"));
}

#[test]
fn test_node_health_validation() {
    // Test valid node health
    let result = validation::validate_node_health("healthy", "health");
    assert!(result.is_ok());
    
    // Test invalid node health with helpful error message
    let result = validation::validate_node_health("sick", "health");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.parameter, "health");
    assert!(error.error.contains("Invalid value: 'sick'"));
    assert!(error.expected.contains("healthy, neutral, unhealthy"));
}

#[test]
fn test_connection_status_validation() {
    // Test valid connection status
    let result = validation::validate_connection_status("online", "connection_status");
    assert!(result.is_ok());
    
    // Test invalid connection status
    let result = validation::validate_connection_status("disconnected", "connection_status");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.expected.contains("online, offline"));
}

#[test]
fn test_boolean_validation_flexible_formats() {
    // Test various true formats
    assert_eq!(validation::validate_boolean("true", "flag").unwrap(), true);
    assert_eq!(validation::validate_boolean("TRUE", "flag").unwrap(), true);
    assert_eq!(validation::validate_boolean("1", "flag").unwrap(), true);
    assert_eq!(validation::validate_boolean("yes", "flag").unwrap(), true);
    assert_eq!(validation::validate_boolean("YES", "flag").unwrap(), true);
    assert_eq!(validation::validate_boolean("on", "flag").unwrap(), true);
    
    // Test various false formats
    assert_eq!(validation::validate_boolean("false", "flag").unwrap(), false);
    assert_eq!(validation::validate_boolean("FALSE", "flag").unwrap(), false);
    assert_eq!(validation::validate_boolean("0", "flag").unwrap(), false);
    assert_eq!(validation::validate_boolean("no", "flag").unwrap(), false);
    assert_eq!(validation::validate_boolean("NO", "flag").unwrap(), false);
    assert_eq!(validation::validate_boolean("off", "flag").unwrap(), false);
    
    // Test invalid boolean with helpful error message
    let result = validation::validate_boolean("maybe", "flag");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.expected.contains("true, false, 1, 0, yes, no, on, off"));
}

#[test]
fn test_range_validation() {
    // Test valid range
    let result = validation::validate_range(50u64, 1u64, 100u64, "limit");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 50);
    
    // Test out of range with specific error message
    let result = validation::validate_range(150u64, 1u64, 100u64, "limit");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.parameter, "limit");
    assert!(error.error.contains("Value 150 is out of range"));
    assert!(error.expected.contains("Value between 1 and 100 (inclusive)"));
}

#[test]
fn test_non_empty_validation() {
    // Test valid non-empty string (with trimming)
    let result = validation::validate_non_empty("  hello  ", "name");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "hello");
    
    // Test empty string
    let result = validation::validate_non_empty("   ", "name");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.error.contains("cannot be empty"));
    assert_eq!(error.expected, "Non-empty string");
}

#[test]
fn test_pattern_validation() {
    // Test alphanumeric pattern
    let result = validation::validate_pattern("test_name-123", "alphanumeric", "name", "Valid name");
    assert!(result.is_ok());
    
    let result = validation::validate_pattern("test@name", "alphanumeric", "name", "Valid name");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.expected.contains("alphanumeric characters, underscores, and hyphens only"));
    
    // Test DNS name pattern
    let result = validation::validate_pattern("example.com", "dns_name", "hostname", "Valid hostname");
    assert!(result.is_ok());
    
    let result = validation::validate_pattern("-invalid.com", "dns_name", "hostname", "Valid hostname");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.error.contains("Invalid DNS name format"));
}

#[test]
fn test_parameter_validation_error_json_format() {
    let mut validation_error = ParameterValidationError::new("Invalid query parameters");
    validation_error.add_error("org_id", "Invalid UUID format: 'not-a-uuid'", "Valid UUID string");
    validation_error.add_error("limit", "Value 2000 is out of range", "Value between 1 and 1000 (inclusive)");
    
    let json = validation_error.to_json();
    
    // Verify JSON structure
    assert_eq!(json["error"], "Invalid query parameters");
    let details = json["details"].as_array().unwrap();
    assert_eq!(details.len(), 2);
    
    // Check first error
    assert_eq!(details[0]["parameter"], "org_id");
    assert_eq!(details[0]["error"], "Invalid UUID format: 'not-a-uuid'");
    assert_eq!(details[0]["expected"], "Valid UUID string");
    
    // Check second error
    assert_eq!(details[1]["parameter"], "limit");
    assert_eq!(details[1]["error"], "Value 2000 is out of range");
    assert_eq!(details[1]["expected"], "Value between 1 and 1000 (inclusive)");
}

#[test]
fn test_multiple_validation_errors() {
    let validations = vec![
        || validation::validate_uuid("not-a-uuid", "org_id").map(|_| ()),
        || validation::validate_range(2000u64, 1u64, 1000u64, "limit").map(|_| ()),
        || validation::validate_node_state("invalid_state", "state"),
    ];
    
    let result = validation::validate_multiple(validations);
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert_eq!(error.errors.len(), 3);
    assert_eq!(error.errors[0].parameter, "org_id");
    assert_eq!(error.errors[1].parameter, "limit");
    assert_eq!(error.errors[2].parameter, "state");
}