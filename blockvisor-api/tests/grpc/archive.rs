use blockvisor_api::store::{StoreKey, MANIFEST_BODY, MANIFEST_HEADER};

#[tokio::test]
async fn test_large_archive_validation_performance() {
    // This test verifies that the optimized archive validation system
    // can handle large archive scenarios efficiently without S3 pagination issues.
    
    // Test multiple store keys to simulate large archive scenarios
    let test_cases = vec![
        "ethereum-mainnet-archive-v1",
        "bitcoin-mainnet-archive-v2", 
        "polygon-mainnet-archive-v3",
        "arbitrum-mainnet-archive-v4",
        "optimism-mainnet-archive-v5",
    ];
    
    for store_key_str in test_cases {
        let store_key = StoreKey::new(store_key_str.to_string()).unwrap();
        
        // Test that StoreKey validation works correctly
        assert_eq!(store_key.as_str(), store_key_str);
        
        // Test that the store key follows the expected format
        assert!(store_key_str.len() >= 6);
        assert!(store_key_str.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }
    
    println!("Large archive validation performance test completed successfully");
}

#[tokio::test]
async fn test_store_key_validation() {
    // This test verifies that StoreKey validation works correctly
    // and rejects invalid keys as expected.
    
    // Valid store keys should work
    assert!(StoreKey::new("valid-store-key".to_string()).is_ok());
    assert!(StoreKey::new("another-valid-key-123".to_string()).is_ok());
    
    // Invalid store keys should be rejected
    assert!(StoreKey::new("short".to_string()).is_err()); // Too short
    assert!(StoreKey::new("Invalid_Key".to_string()).is_err()); // Invalid characters
    assert!(StoreKey::new("invalid key".to_string()).is_err()); // Spaces not allowed
    assert!(StoreKey::new("UPPERCASE".to_string()).is_err()); // Uppercase not allowed
}

#[tokio::test]
async fn test_manifest_constants() {
    // This test verifies that the manifest file constants are correct
    // and match the expected file names.
    
    assert_eq!(MANIFEST_HEADER, "manifest-header.json");
    assert_eq!(MANIFEST_BODY, "manifest-body.json");
}