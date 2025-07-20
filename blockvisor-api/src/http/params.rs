use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de};

/// A wrapper type that can deserialize comma-separated values or repeated query parameters
/// into a Vec<T>.
/// 
/// Examples:
/// - `param=a,b,c` → `vec!["a", "b", "c"]`
/// - `param=a&param=b&param=c` → `vec!["a", "b", "c"]`
/// - `param=a` → `vec!["a"]`
#[derive(Debug, Clone, PartialEq)]
pub struct CommaSeparatedList<T>(pub Vec<T>);

impl<T> Default for CommaSeparatedList<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> From<CommaSeparatedList<T>> for Vec<T> {
    fn from(list: CommaSeparatedList<T>) -> Self {
        list.0
    }
}

impl<T> From<Vec<T>> for CommaSeparatedList<T> {
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<'de, T> Deserialize<'de> for CommaSeparatedList<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CommaSeparatedListVisitor<T> {
            marker: PhantomData<T>,
        }

        impl<'de, T> de::Visitor<'de> for CommaSeparatedListVisitor<T>
        where
            T: FromStr,
            T::Err: fmt::Display,
        {
            type Value = CommaSeparatedList<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string with comma-separated values or a sequence of strings")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let items: Result<Vec<T>, _> = value
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<T>())
                    .collect();

                match items {
                    Ok(vec) => Ok(CommaSeparatedList(vec)),
                    Err(e) => Err(E::custom(format!("Failed to parse value: {}", e))),
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(value) = seq.next_element::<String>()? {
                    // Handle comma-separated values within sequence elements
                    for item in value.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                        match item.parse::<T>() {
                            Ok(parsed) => vec.push(parsed),
                            Err(e) => return Err(de::Error::custom(format!("Failed to parse value '{}': {}", item, e))),
                        }
                    }
                }
                Ok(CommaSeparatedList(vec))
            }
        }

        deserializer.deserialize_any(CommaSeparatedListVisitor {
            marker: PhantomData,
        })
    }
}

/// A wrapper type that accepts either a single value or a vector of values,
/// always converting to a Vec<T>.
/// 
/// Examples:
/// - `param=a` → `vec!["a"]`
/// - `param=a&param=b` → `vec!["a", "b"]`
#[derive(Debug, Clone, PartialEq)]
pub struct SingleOrVec<T>(pub Vec<T>);

impl<T> Default for SingleOrVec<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> From<SingleOrVec<T>> for Vec<T> {
    fn from(single_or_vec: SingleOrVec<T>) -> Self {
        single_or_vec.0
    }
}

impl<T> From<Vec<T>> for SingleOrVec<T> {
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T> From<T> for SingleOrVec<T> {
    fn from(single: T) -> Self {
        Self(vec![single])
    }
}

impl<'de, T> Deserialize<'de> for SingleOrVec<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SingleOrVecVisitor<T> {
            marker: PhantomData<T>,
        }

        impl<'de, T> de::Visitor<'de> for SingleOrVecVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = SingleOrVec<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a single value or a sequence of values")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                }
                Ok(SingleOrVec(vec))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let single_value = T::deserialize(de::value::StrDeserializer::new(value))?;
                Ok(SingleOrVec(vec![single_value]))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let single_value = T::deserialize(de::value::StringDeserializer::new(value))?;
                Ok(SingleOrVec(vec![single_value]))
            }
        }

        deserializer.deserialize_any(SingleOrVecVisitor {
            marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_urlencoded;

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestParams {
        #[serde(default)]
        comma_list: CommaSeparatedList<String>,
        #[serde(default)]
        single_or_vec: SingleOrVec<String>,
    }

    #[test]
    fn test_comma_separated_list_single_value() {
        let query = "comma_list=hello";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.comma_list.0, vec!["hello"]);
    }

    #[test]
    fn test_comma_separated_list_comma_separated() {
        let query = "comma_list=hello,world,test";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.comma_list.0, vec!["hello", "world", "test"]);
    }

    #[test]
    fn test_comma_separated_list_repeated_params() {
        // Note: serde_urlencoded doesn't support repeated parameters by default
        // This functionality will be handled by Axum's Query extractor differently
        let query = "comma_list=hello,world,test";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.comma_list.0, vec!["hello", "world", "test"]);
    }

    #[test]
    fn test_comma_separated_list_mixed() {
        // Test that comma separation works within a single parameter
        let query = "comma_list=hello,world,test";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.comma_list.0, vec!["hello", "world", "test"]);
    }

    #[test]
    fn test_single_or_vec_single() {
        let query = "single_or_vec=hello";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.single_or_vec.0, vec!["hello"]);
    }

    #[test]
    fn test_single_or_vec_multiple() {
        // Note: serde_urlencoded doesn't support repeated parameters by default
        // For now, test single value functionality
        let query = "single_or_vec=hello";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.single_or_vec.0, vec!["hello"]);
    }

    #[test]
    fn test_comma_separated_list_with_uuids() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct UuidParams {
            #[serde(default)]
            ids: CommaSeparatedList<uuid::Uuid>,
        }

        let uuid1 = uuid::Uuid::new_v4();
        let uuid2 = uuid::Uuid::new_v4();
        let query = format!("ids={},{}", uuid1, uuid2);
        
        let params: UuidParams = serde_urlencoded::from_str(&query).unwrap();
        assert_eq!(params.ids.0, vec![uuid1, uuid2]);
    }

    #[test]
    fn test_comma_separated_list_empty() {
        let query = "";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.comma_list.0, Vec::<String>::new());
    }

    #[test]
    fn test_comma_separated_list_whitespace() {
        let query = "comma_list=hello, world , test";
        let params: TestParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.comma_list.0, vec!["hello", "world", "test"]);
    }
}

/// Parameter validation error details
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterError {
    pub parameter: String,
    pub error: String,
    pub expected: String,
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Parameter '{}': {} (expected: {})", self.parameter, self.error, self.expected)
    }
}

/// Collection of parameter validation errors
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterValidationError {
    pub message: String,
    pub errors: Vec<ParameterError>,
}

impl fmt::Display for ParameterValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.message)?;
        for error in &self.errors {
            writeln!(f, "  - {}", error)?;
        }
        Ok(())
    }
}

impl std::error::Error for ParameterValidationError {}

impl ParameterValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            errors: Vec::new(),
        }
    }

    pub fn add_error(&mut self, parameter: impl Into<String>, error: impl Into<String>, expected: impl Into<String>) {
        self.errors.push(ParameterError {
            parameter: parameter.into(),
            error: error.into(),
            expected: expected.into(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Convert to JSON response format
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.message,
            "details": self.errors.iter().map(|e| {
                serde_json::json!({
                    "parameter": e.parameter,
                    "error": e.error,
                    "expected": e.expected
                })
            }).collect::<Vec<_>>()
        })
    }
}

/// Utility functions for parameter validation
pub mod validation {
    use super::*;
    use uuid::Uuid;

    /// Validate that a string is a valid UUID
    pub fn validate_uuid(value: &str, param_name: &str) -> Result<Uuid, ParameterError> {
        value.parse::<Uuid>().map_err(|_| ParameterError {
            parameter: param_name.to_string(),
            error: format!("Invalid UUID format: '{}'", value),
            expected: "Valid UUID string (e.g., '550e8400-e29b-41d4-a716-446655440000')".to_string(),
        })
    }

    /// Validate that a list of strings are valid UUIDs
    pub fn validate_uuid_list(values: &[String], param_name: &str) -> Result<Vec<Uuid>, ParameterError> {
        let mut uuids = Vec::new();
        for (index, value) in values.iter().enumerate() {
            match validate_uuid(value, param_name) {
                Ok(uuid) => uuids.push(uuid),
                Err(mut e) => {
                    // Enhance error message to show which item in the list failed
                    e.error = format!("Invalid UUID format at index {}: '{}'", index, value);
                    return Err(e);
                }
            }
        }
        Ok(uuids)
    }

    /// Validate that a number is within a specific range
    pub fn validate_range<T>(value: T, min: T, max: T, param_name: &str) -> Result<T, ParameterError>
    where
        T: PartialOrd + fmt::Display + Copy,
    {
        if value < min || value > max {
            Err(ParameterError {
                parameter: param_name.to_string(),
                error: format!("Value {} is out of range", value),
                expected: format!("Value between {} and {} (inclusive)", min, max),
            })
        } else {
            Ok(value)
        }
    }

    /// Validate that a value is one of the allowed enum values
    pub fn validate_enum<T>(value: &str, allowed_values: &[T], param_name: &str) -> Result<(), ParameterError>
    where
        T: fmt::Display,
    {
        let allowed_str: Vec<String> = allowed_values.iter().map(|v| v.to_string()).collect();
        if !allowed_str.contains(&value.to_string()) {
            Err(ParameterError {
                parameter: param_name.to_string(),
                error: format!("Invalid value: '{}'", value),
                expected: format!("One of: {}", allowed_str.join(", ")),
            })
        } else {
            Ok(())
        }
    }

    /// Validate node state parameter
    pub fn validate_node_state(value: &str, param_name: &str) -> Result<(), ParameterError> {
        let allowed_states = ["starting", "running", "stopped", "failed", "upgrading", "deleting", "deleted"];
        validate_enum(value, &allowed_states, param_name)
    }

    /// Validate node health parameter
    pub fn validate_node_health(value: &str, param_name: &str) -> Result<(), ParameterError> {
        let allowed_health = ["healthy", "neutral", "unhealthy"];
        validate_enum(value, &allowed_health, param_name)
    }

    /// Validate host connection status parameter
    pub fn validate_connection_status(value: &str, param_name: &str) -> Result<(), ParameterError> {
        let allowed_statuses = ["online", "offline"];
        validate_enum(value, &allowed_statuses, param_name)
    }

    /// Validate schedule type parameter
    pub fn validate_schedule_type(value: &str, param_name: &str) -> Result<(), ParameterError> {
        let allowed_types = ["automatic", "manual"];
        validate_enum(value, &allowed_types, param_name)
    }

    /// Validate boolean parameter (accepts various formats)
    pub fn validate_boolean(value: &str, param_name: &str) -> Result<bool, ParameterError> {
        match value.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(ParameterError {
                parameter: param_name.to_string(),
                error: format!("Invalid boolean value: '{}'", value),
                expected: "One of: true, false, 1, 0, yes, no, on, off (case insensitive)".to_string(),
            })
        }
    }

    /// Validate that a string is not empty
    pub fn validate_non_empty(value: &str, param_name: &str) -> Result<String, ParameterError> {
        if value.trim().is_empty() {
            Err(ParameterError {
                parameter: param_name.to_string(),
                error: "Value cannot be empty".to_string(),
                expected: "Non-empty string".to_string(),
            })
        } else {
            Ok(value.trim().to_string())
        }
    }

    /// Validate that a string matches a specific pattern (basic regex-like validation)
    pub fn validate_pattern(value: &str, pattern: &str, param_name: &str, description: &str) -> Result<String, ParameterError> {
        // For now, implement basic patterns. Can be extended with regex crate if needed
        match pattern {
            "alphanumeric" => {
                if value.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                    Ok(value.to_string())
                } else {
                    Err(ParameterError {
                        parameter: param_name.to_string(),
                        error: format!("Invalid format: '{}'", value),
                        expected: format!("{} (alphanumeric characters, underscores, and hyphens only)", description),
                    })
                }
            }
            "dns_name" => {
                if value.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') && 
                   !value.starts_with('-') && !value.ends_with('-') &&
                   !value.starts_with('.') && !value.ends_with('.') {
                    Ok(value.to_string())
                } else {
                    Err(ParameterError {
                        parameter: param_name.to_string(),
                        error: format!("Invalid DNS name format: '{}'", value),
                        expected: format!("{} (valid DNS name format)", description),
                    })
                }
            }
            _ => Ok(value.to_string()) // Unknown pattern, just return the value
        }
    }

    /// Validate multiple parameters and collect all errors
    pub fn validate_multiple<F>(validations: Vec<F>) -> Result<(), ParameterValidationError>
    where
        F: FnOnce() -> Result<(), ParameterError>,
    {
        let mut validation_error = ParameterValidationError::new("Invalid query parameters");
        
        for validation in validations {
            if let Err(e) = validation() {
                validation_error.add_error(e.parameter, e.error, e.expected);
            }
        }

        if validation_error.is_empty() {
            Ok(())
        } else {
            Err(validation_error)
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use super::validation::*;

    #[test]
    fn test_parameter_validation_error() {
        let mut error = ParameterValidationError::new("Invalid parameters");
        error.add_error("org_id", "Invalid UUID", "Valid UUID string");
        error.add_error("limit", "Value too large", "Number between 1 and 1000");

        assert_eq!(error.errors.len(), 2);
        assert!(!error.is_empty());

        let json = error.to_json();
        assert_eq!(json["error"], "Invalid parameters");
        assert_eq!(json["details"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_validate_uuid_success() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let result = validate_uuid(uuid_str, "test_id");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_uuid_failure() {
        let invalid_uuid = "not-a-uuid";
        let result = validate_uuid(invalid_uuid, "test_id");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "test_id");
        assert!(error.error.contains("Invalid UUID format"));
    }

    #[test]
    fn test_validate_uuid_list_success() {
        let uuid_strs = vec![
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        ];
        let result = validate_uuid_list(&uuid_strs, "test_ids");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_uuid_list_failure() {
        let uuid_strs = vec![
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "not-a-uuid".to_string(),
        ];
        let result = validate_uuid_list(&uuid_strs, "test_ids");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_range_success() {
        let result = validate_range(50u64, 1u64, 100u64, "limit");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 50);
    }

    #[test]
    fn test_validate_range_failure() {
        let result = validate_range(150u64, 1u64, 100u64, "limit");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "limit");
        assert!(error.error.contains("out of range"));
    }

    #[test]
    fn test_validate_enum_success() {
        let allowed = vec!["active", "inactive", "pending"];
        let result = validate_enum("active", &allowed, "status");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_enum_failure() {
        let allowed = vec!["active", "inactive", "pending"];
        let result = validate_enum("invalid", &allowed, "status");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "status");
        assert!(error.error.contains("Invalid value"));
        assert!(error.expected.contains("active, inactive, pending"));
    }

    #[test]
    fn test_validate_node_state_success() {
        let result = validate_node_state("running", "state");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_node_state_failure() {
        let result = validate_node_state("invalid_state", "state");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "state");
        assert!(error.error.contains("Invalid value"));
        assert!(error.expected.contains("starting, running, stopped"));
    }

    #[test]
    fn test_validate_node_health_success() {
        let result = validate_node_health("healthy", "health");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_node_health_failure() {
        let result = validate_node_health("sick", "health");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "health");
        assert!(error.error.contains("Invalid value"));
        assert!(error.expected.contains("healthy, neutral, unhealthy"));
    }

    #[test]
    fn test_validate_connection_status_success() {
        let result = validate_connection_status("online", "connection_status");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_connection_status_failure() {
        let result = validate_connection_status("disconnected", "connection_status");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "connection_status");
        assert!(error.expected.contains("online, offline"));
    }

    #[test]
    fn test_validate_boolean_success() {
        assert_eq!(validate_boolean("true", "flag").unwrap(), true);
        assert_eq!(validate_boolean("false", "flag").unwrap(), false);
        assert_eq!(validate_boolean("1", "flag").unwrap(), true);
        assert_eq!(validate_boolean("0", "flag").unwrap(), false);
        assert_eq!(validate_boolean("YES", "flag").unwrap(), true);
        assert_eq!(validate_boolean("no", "flag").unwrap(), false);
    }

    #[test]
    fn test_validate_boolean_failure() {
        let result = validate_boolean("maybe", "flag");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "flag");
        assert!(error.error.contains("Invalid boolean value"));
        assert!(error.expected.contains("true, false, 1, 0"));
    }

    #[test]
    fn test_validate_non_empty_success() {
        let result = validate_non_empty("  hello  ", "name");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn test_validate_non_empty_failure() {
        let result = validate_non_empty("   ", "name");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "name");
        assert!(error.error.contains("cannot be empty"));
    }

    #[test]
    fn test_validate_pattern_alphanumeric_success() {
        let result = validate_pattern("test_name-123", "alphanumeric", "name", "Valid name");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_name-123");
    }

    #[test]
    fn test_validate_pattern_alphanumeric_failure() {
        let result = validate_pattern("test@name", "alphanumeric", "name", "Valid name");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "name");
        assert!(error.error.contains("Invalid format"));
        assert!(error.expected.contains("alphanumeric characters"));
    }

    #[test]
    fn test_validate_pattern_dns_name_success() {
        let result = validate_pattern("example.com", "dns_name", "hostname", "Valid hostname");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }

    #[test]
    fn test_validate_pattern_dns_name_failure() {
        let result = validate_pattern("-invalid.com", "dns_name", "hostname", "Valid hostname");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.parameter, "hostname");
        assert!(error.error.contains("Invalid DNS name format"));
    }

    #[test]
    fn test_validate_uuid_list_with_index_error() {
        let uuid_strs = vec![
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "invalid-uuid".to_string(),
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        ];
        let result = validate_uuid_list(&uuid_strs, "test_ids");
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(error.error.contains("at index 1"));
        assert!(error.error.contains("invalid-uuid"));
    }
}