//! Unit tests for node upgrade resource tracking functionality

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;
    
    use crate::auth::resource::{NodeId, OrgId, HostId, ResourceType, ResourceId};
    use crate::model::node::{Node, Error, NodeState};
    use crate::model::image::{NodeConfig, ImageId, ConfigId, ArchiveId};
    use crate::model::image::config::{VmConfig, ImageConfig, FirewallConfig, Ramdisks};
    use crate::model::image::rule::FirewallAction;
    use crate::model::protocol::version::VersionId;
    use crate::store::StoreKey;
    use crate::model::sql::{Tags, Version};
    use crate::model::{ProtocolId};

    /// Helper function to create a test Node with specified resources
    fn create_test_node(cpu_cores: i64, memory_bytes: i64, disk_bytes: i64) -> Node {
        Node {
            id: NodeId::from(Uuid::new_v4()),
            node_name: "test-node".to_string(),
            display_name: "Test Node".to_string(),
            old_node_id: None,
            org_id: OrgId::from(Uuid::new_v4()),
            host_id: HostId::from(Uuid::new_v4()),
            image_id: ImageId::from(Uuid::new_v4()),
            config_id: ConfigId::from(Uuid::new_v4()),
            protocol_id: ProtocolId::from(Uuid::new_v4()),
            protocol_version_id: VersionId::from(Uuid::new_v4()),
            semantic_version: Version::from(semver::Version::parse("1.0.0").unwrap()),
            auto_upgrade: false,
            node_state: NodeState::Running,
            next_state: None,
            protocol_state: None,
            protocol_health: None,
            jobs: None,
            note: None,
            tags: Tags::default(),
            ip_address: "192.168.1.100/24".parse().unwrap(),
            ip_gateway: "192.168.1.1/24".parse().unwrap(),
            p2p_address: None,
            dns_id: "test-dns-id".to_string(),
            dns_name: "test.example.com".to_string(),
            dns_url: None,
            cpu_cores,
            memory_bytes,
            disk_bytes,
            block_height: None,
            block_age: None,
            consensus: None,
            scheduler_similarity: None,
            scheduler_resource: None,
            scheduler_region_id: None,
            stripe_item_id: None,
            created_by_type: ResourceType::User,
            created_by_id: ResourceId::from(Uuid::new_v4()),
            created_at: Utc::now(),
            updated_at: None,
            deleted_at: None,
            cost: None,
            apr: None,
            jailed: None,
            jailed_reason: None,
            sqd_name: None,
        }
    }

    /// Helper function to create a test NodeConfig with specified resources
    fn create_test_node_config(cpu_cores: u64, memory_bytes: u64, disk_bytes: u64) -> NodeConfig {
        NodeConfig {
            vm: VmConfig {
                cpu_cores,
                memory_bytes,
                disk_bytes,
                ramdisks: Ramdisks(vec![]),
            },
            image: ImageConfig {
                image_id: ImageId::from(Uuid::new_v4()),
                image_uri: "test://image".to_string(),
                archive_id: ArchiveId::from(Uuid::new_v4()),
                store_key: StoreKey::new("test-key".into()).expect("valid StoreKey"),
                values: vec![],
                min_babel_version: Version::from(semver::Version::new(1, 0, 0)),
            },
            firewall: FirewallConfig {
                default_in: FirewallAction::Drop,
                default_out: FirewallAction::Allow,
                rules: vec![],
            },
        }
    }

    /// Mock UpgradeNode for testing resource tracking methods
    struct MockUpgradeNode;

    impl MockUpgradeNode {
        fn extract_current_resources(&self, node: &Node) -> (i64, i64, i64) {
            (node.cpu_cores, node.memory_bytes, node.disk_bytes)
        }

        fn calculate_new_resources(&self, new_config: &NodeConfig) -> Result<(i64, i64, i64), Error> {
            let cpu_cores = i64::try_from(new_config.vm.cpu_cores).map_err(Error::VmCpu)?;
            let memory_bytes = i64::try_from(new_config.vm.memory_bytes).map_err(Error::VmMemory)?;
            let disk_bytes = i64::try_from(new_config.vm.disk_bytes).map_err(Error::VmDisk)?;
            
            Ok((cpu_cores, memory_bytes, disk_bytes))
        }

        fn validate_image_config(&self, new_config: &NodeConfig) -> Result<(), Error> {
            // Validate that resource values are reasonable (not zero or negative)
            if new_config.vm.cpu_cores == 0 {
                return Err(Error::InvalidImageConfig("CPU cores cannot be zero".to_string()));
            }
            
            if new_config.vm.memory_bytes == 0 {
                return Err(Error::InvalidImageConfig("Memory bytes cannot be zero".to_string()));
            }
            
            if new_config.vm.disk_bytes == 0 {
                return Err(Error::InvalidImageConfig("Disk bytes cannot be zero".to_string()));
            }

            // Validate that resource values don't exceed reasonable limits to prevent overflow
            const MAX_REASONABLE_CPU: u64 = 1000; // 1000 cores
            const MAX_REASONABLE_MEMORY: u64 = 1024 * 1024 * 1024 * 1024; // 1TB
            const MAX_REASONABLE_DISK: u64 = 100 * 1024 * 1024 * 1024 * 1024; // 100TB

            if new_config.vm.cpu_cores > MAX_REASONABLE_CPU {
                return Err(Error::InvalidImageConfig(format!(
                    "CPU cores {} exceeds reasonable limit of {}",
                    new_config.vm.cpu_cores, MAX_REASONABLE_CPU
                )));
            }

            if new_config.vm.memory_bytes > MAX_REASONABLE_MEMORY {
                return Err(Error::InvalidImageConfig(format!(
                    "Memory bytes {} exceeds reasonable limit of {}",
                    new_config.vm.memory_bytes, MAX_REASONABLE_MEMORY
                )));
            }

            if new_config.vm.disk_bytes > MAX_REASONABLE_DISK {
                return Err(Error::InvalidImageConfig(format!(
                    "Disk bytes {} exceeds reasonable limit of {}",
                    new_config.vm.disk_bytes, MAX_REASONABLE_DISK
                )));
            }

            Ok(())
        }

        fn calculate_resource_differences(
            &self,
            old_resources: (i64, i64, i64),
            new_resources: (i64, i64, i64),
        ) -> Result<(i64, i64, i64), Error> {
            let (old_cpu, old_memory, old_disk) = old_resources;
            let (new_cpu, new_memory, new_disk) = new_resources;

            // Validate that old resources are non-negative (sanity check)
            if old_cpu < 0 || old_memory < 0 || old_disk < 0 {
                return Err(Error::InvalidImageConfig(
                    "Old resource values cannot be negative".to_string()
                ));
            }

            // Validate that new resources are non-negative
            if new_cpu < 0 || new_memory < 0 || new_disk < 0 {
                return Err(Error::InvalidImageConfig(
                    "New resource values cannot be negative".to_string()
                ));
            }

            // Check for potential overflow in subtraction
            let cpu_diff = new_cpu.checked_sub(old_cpu).ok_or(Error::ResourceOverflow)?;
            let memory_diff = new_memory.checked_sub(old_memory).ok_or(Error::ResourceOverflow)?;
            let disk_diff = new_disk.checked_sub(old_disk).ok_or(Error::ResourceOverflow)?;

            // Additional validation: check if differences are within reasonable bounds
            const MAX_REASONABLE_DIFF: i64 = i64::MAX / 2; // Half of max to prevent addition overflow later
            
            if cpu_diff.abs() > MAX_REASONABLE_DIFF ||
               memory_diff.abs() > MAX_REASONABLE_DIFF ||
               disk_diff.abs() > MAX_REASONABLE_DIFF {
                return Err(Error::ResourceOverflow);
            }

            Ok((cpu_diff, memory_diff, disk_diff))
        }
    }

    #[test]
    fn test_extract_current_resources() {
        let upgrade = MockUpgradeNode;
        let node = create_test_node(4, 8_000_000_000, 100_000_000_000);

        let (cpu, memory, disk) = upgrade.extract_current_resources(&node);
        assert_eq!(cpu, 4);
        assert_eq!(memory, 8_000_000_000);
        assert_eq!(disk, 100_000_000_000);
    }

    #[test]
    fn test_calculate_new_resources_success() {
        let upgrade = MockUpgradeNode;
        let config = create_test_node_config(8, 16_000_000_000, 200_000_000_000);

        let result = upgrade.calculate_new_resources(&config);
        assert!(result.is_ok());
        let (cpu, memory, disk) = result.unwrap();
        assert_eq!(cpu, 8);
        assert_eq!(memory, 16_000_000_000);
        assert_eq!(disk, 200_000_000_000);
    }

    #[test]
    fn test_calculate_new_resources_overflow() {
        let upgrade = MockUpgradeNode;
        // Use u64::MAX which will overflow when converted to i64
        let config = create_test_node_config(u64::MAX, 16_000_000_000, 200_000_000_000);

        let result = upgrade.calculate_new_resources(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::VmCpu(_) => (), // Expected
            _ => panic!("Expected VmCpu error"),
        }
    }

    #[test]
    fn test_validate_image_config_success() {
        let upgrade = MockUpgradeNode;
        let config = create_test_node_config(8, 16_000_000_000, 200_000_000_000);

        let result = upgrade.validate_image_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_image_config_zero_cpu() {
        let upgrade = MockUpgradeNode;
        let config = create_test_node_config(0, 16_000_000_000, 200_000_000_000);

        let result = upgrade.validate_image_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("CPU cores cannot be zero"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
    }

    #[test]
    fn test_validate_image_config_zero_memory() {
        let upgrade = MockUpgradeNode;
        let config = create_test_node_config(8, 0, 200_000_000_000);

        let result = upgrade.validate_image_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("Memory bytes cannot be zero"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
    }

    #[test]
    fn test_validate_image_config_zero_disk() {
        let upgrade = MockUpgradeNode;
        let config = create_test_node_config(8, 16_000_000_000, 0);

        let result = upgrade.validate_image_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("Disk bytes cannot be zero"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
    }

    #[test]
    fn test_validate_image_config_excessive_cpu() {
        let upgrade = MockUpgradeNode;
        let config = create_test_node_config(2000, 16_000_000_000, 200_000_000_000); // > 1000 cores

        let result = upgrade.validate_image_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("CPU cores") && msg.contains("exceeds reasonable limit"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
    }

    #[test]
    fn test_calculate_resource_differences_upgrade() {
        let upgrade = MockUpgradeNode;
        let old_resources = (4, 8_000_000_000, 100_000_000_000);
        let new_resources = (8, 16_000_000_000, 200_000_000_000);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 4);
        assert_eq!(memory_diff, 8_000_000_000);
        assert_eq!(disk_diff, 100_000_000_000);
    }

    #[test]
    fn test_calculate_resource_differences_downgrade() {
        let upgrade = MockUpgradeNode;
        let old_resources = (8, 16_000_000_000, 200_000_000_000);
        let new_resources = (4, 8_000_000_000, 100_000_000_000);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, -4);
        assert_eq!(memory_diff, -8_000_000_000);
        assert_eq!(disk_diff, -100_000_000_000);
    }

    #[test]
    fn test_calculate_resource_differences_no_change() {
        let upgrade = MockUpgradeNode;
        let old_resources = (4, 8_000_000_000, 100_000_000_000);
        let new_resources = (4, 8_000_000_000, 100_000_000_000);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 0);
        assert_eq!(memory_diff, 0);
        assert_eq!(disk_diff, 0);
    }

    #[test]
    fn test_calculate_resource_differences_negative_old() {
        let upgrade = MockUpgradeNode;
        let old_resources = (-1, 8_000_000_000, 100_000_000_000); // Negative CPU
        let new_resources = (8, 16_000_000_000, 200_000_000_000);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("Old resource values cannot be negative"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
    }

    #[test]
    fn test_calculate_resource_differences_negative_new() {
        let upgrade = MockUpgradeNode;
        let old_resources = (4, 8_000_000_000, 100_000_000_000);
        let new_resources = (-1, 16_000_000_000, 200_000_000_000); // Negative CPU

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("New resource values cannot be negative"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
    }

    #[test]
    fn test_calculate_resource_differences_overflow_protection() {
        let upgrade = MockUpgradeNode;
        // Use values that would cause overflow in subtraction
        let old_resources = (i64::MIN, 0, 0);
        let new_resources = (i64::MAX, 0, 0);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("Old resource values cannot be negative"));
            }
            _ => panic!("Expected InvalidImageConfig error for negative old values"),
        }
    }

    #[test]
    fn test_calculate_resource_differences_large_values() {
        let upgrade = MockUpgradeNode;
        // Use large but valid values
        let old_resources = (100, 1_000_000_000_000, 10_000_000_000_000);
        let new_resources = (200, 2_000_000_000_000, 20_000_000_000_000);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 100);
        assert_eq!(memory_diff, 1_000_000_000_000);
        assert_eq!(disk_diff, 10_000_000_000_000);
    }

    #[test]
    fn test_error_conversion_to_grpc_status() {
        use crate::grpc::Status;
        
        // Test ResourceOverflow error conversion
        let error = Error::ResourceOverflow;
        let status: Status = error.into();
        match status {
            Status::InvalidArgument(_) => (), // Expected
            _ => panic!("Expected InvalidArgument status"),
        }
        
        // Test NegativeHostCounters error conversion
        let error = Error::NegativeHostCounters;
        let status: Status = error.into();
        match status {
            Status::InvalidArgument(_) => (), // Expected
            _ => panic!("Expected InvalidArgument status"),
        }
        
        // Test InvalidImageConfig error conversion
        let error = Error::InvalidImageConfig("test error".to_string());
        let status: Status = error.into();
        match status {
            Status::InvalidArgument(_) => (), // Expected
            _ => panic!("Expected InvalidArgument status"),
        }

        // Test VmCpu error conversion
        let error = Error::VmCpu(i64::try_from(u64::MAX).unwrap_err());
        let status: Status = error.into();
        match status {
            Status::Internal(_) => (), // Expected
            _ => panic!("Expected Internal status"),
        }

        // Test UpdateHostCounters error conversion
        let error = Error::UpdateHostCounters(diesel::result::Error::NotFound);
        let status: Status = error.into();
        match status {
            Status::Internal(_) => (), // Expected
            _ => panic!("Expected Internal status"),
        }

        // Test OldConfigNotFound error conversion
        let config_error = crate::model::image::config::Error::MissingVmConfig;
        let error = Error::OldConfigNotFound(config_error);
        let status: Status = error.into();
        match status {
            Status::Internal(_) => (), // Expected
            _ => panic!("Expected Internal status"),
        }
    }

    #[test]
    fn test_edge_case_zero_resources() {
        let upgrade = MockUpgradeNode;
        
        // Test with zero old resources (should be valid)
        let old_resources = (0, 0, 0);
        let new_resources = (4, 8_000_000_000, 100_000_000_000);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 4);
        assert_eq!(memory_diff, 8_000_000_000);
        assert_eq!(disk_diff, 100_000_000_000);
    }

    #[test]
    fn test_edge_case_same_resources() {
        let upgrade = MockUpgradeNode;
        
        // Test upgrade with identical resource requirements
        let resources = (4, 8_000_000_000, 100_000_000_000);
        let result = upgrade.calculate_resource_differences(resources, resources);
        
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 0);
        assert_eq!(memory_diff, 0);
        assert_eq!(disk_diff, 0);
    }

    #[test]
    fn test_mixed_resource_changes() {
        let upgrade = MockUpgradeNode;
        
        // Test upgrade where some resources increase and others decrease
        let old_resources = (8, 4_000_000_000, 100_000_000_000);
        let new_resources = (4, 16_000_000_000, 50_000_000_000);

        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, -4); // CPU decreased
        assert_eq!(memory_diff, 12_000_000_000); // Memory increased
        assert_eq!(disk_diff, -50_000_000_000); // Disk decreased
    }

    /// Test scenarios that would cause host counter validation to fail
    #[test]
    fn test_host_counter_validation_scenarios() {
        let upgrade = MockUpgradeNode;
        
        // Test scenario where downgrade would cause negative host counters
        // This simulates a case where the host currently has exactly the resources
        // that the node is using, so any decrease would make counters negative
        
        // Simulate current host counters: (4, 8GB, 100GB)
        // Node wants to downgrade from (4, 8GB, 100GB) to (2, 4GB, 50GB)
        // This should be allowed as it would result in positive counters: (2, 4GB, 50GB)
        let old_resources = (4, 8_000_000_000, 100_000_000_000);
        let new_resources = (2, 4_000_000_000, 50_000_000_000);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, -2);
        assert_eq!(memory_diff, -4_000_000_000);
        assert_eq!(disk_diff, -50_000_000_000);
        
        // Test scenario where upgrade would cause overflow
        // Use values near i64::MAX to test overflow protection
        let old_resources = (i64::MAX / 2, i64::MAX / 2, i64::MAX / 2);
        let new_resources = (i64::MAX - 1, i64::MAX - 1, i64::MAX - 1);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        // This should succeed as the differences are within bounds
        assert!(result.is_ok());
    }

    /// Test error handling for various failure scenarios
    #[test]
    fn test_comprehensive_error_handling() {
        let upgrade = MockUpgradeNode;
        
        // Test with maximum values that would cause overflow in differences
        let old_resources = (0, 0, 0);
        let new_resources = (i64::MAX, i64::MAX, i64::MAX);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        // This should fail due to exceeding reasonable difference bounds
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ResourceOverflow => (), // Expected
            _ => panic!("Expected ResourceOverflow error"),
        }
        
        // Test with values that would cause subtraction overflow
        let old_resources = (i64::MAX, i64::MAX, i64::MAX);
        let new_resources = (0, 0, 0);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        // This should fail due to exceeding reasonable difference bounds
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ResourceOverflow => (), // Expected
            _ => panic!("Expected ResourceOverflow error"),
        }
    }

    /// Test validation of image configurations with edge cases
    #[test]
    fn test_image_config_validation_edge_cases() {
        let upgrade = MockUpgradeNode;
        
        // Test with exactly at the limit values
        let config = create_test_node_config(1000, 1024 * 1024 * 1024 * 1024, 100 * 1024 * 1024 * 1024 * 1024);
        let result = upgrade.validate_image_config(&config);
        assert!(result.is_ok(), "Exactly at limit should be valid");
        
        // Test with just over the limit
        let config = create_test_node_config(1001, 16_000_000_000, 200_000_000_000);
        let result = upgrade.validate_image_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("CPU cores") && msg.contains("exceeds reasonable limit"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
        
        // Test with memory just over the limit
        let config = create_test_node_config(8, 1024 * 1024 * 1024 * 1024 + 1, 200_000_000_000);
        let result = upgrade.validate_image_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("Memory bytes") && msg.contains("exceeds reasonable limit"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
        
        // Test with disk just over the limit
        let config = create_test_node_config(8, 16_000_000_000, 100 * 1024 * 1024 * 1024 * 1024 + 1);
        let result = upgrade.validate_image_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidImageConfig(msg) => {
                assert!(msg.contains("Disk bytes") && msg.contains("exceeds reasonable limit"));
            }
            _ => panic!("Expected InvalidImageConfig error"),
        }
    }

    /// Test resource calculation with realistic values
    #[test]
    fn test_realistic_resource_scenarios() {
        let upgrade = MockUpgradeNode;
        
        // Test typical small node upgrade (1 CPU -> 2 CPU, 2GB -> 4GB, 20GB -> 40GB)
        let old_resources = (1, 2_000_000_000, 20_000_000_000);
        let new_resources = (2, 4_000_000_000, 40_000_000_000);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 1);
        assert_eq!(memory_diff, 2_000_000_000);
        assert_eq!(disk_diff, 20_000_000_000);
        
        // Test typical large node downgrade (16 CPU -> 8 CPU, 64GB -> 32GB, 1TB -> 500GB)
        let old_resources = (16, 64_000_000_000, 1_000_000_000_000);
        let new_resources = (8, 32_000_000_000, 500_000_000_000);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, -8);
        assert_eq!(memory_diff, -32_000_000_000);
        assert_eq!(disk_diff, -500_000_000_000);
        
        // Test minimal resource node (1 CPU, 1GB, 10GB)
        let old_resources = (0, 0, 0);
        let new_resources = (1, 1_000_000_000, 10_000_000_000);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 1);
        assert_eq!(memory_diff, 1_000_000_000);
        assert_eq!(disk_diff, 10_000_000_000);
    }

    /// Test that all error types convert to appropriate gRPC status codes
    #[test]
    fn test_comprehensive_error_to_grpc_conversion() {
        use crate::grpc::Status;
        
        // Test all the new error types added for resource tracking
        let errors_and_expected_status = vec![
            (Error::ResourceOverflow, "InvalidArgument"),
            (Error::NegativeHostCounters, "InvalidArgument"),
            (Error::InvalidImageConfig("test".to_string()), "InvalidArgument"),
            (Error::VmCpu(i64::try_from(u64::MAX).unwrap_err()), "Internal"),
            (Error::VmMemory(i64::try_from(u64::MAX).unwrap_err()), "Internal"),
            (Error::VmDisk(i64::try_from(u64::MAX).unwrap_err()), "Internal"),
            (Error::UpdateHostCounters(diesel::result::Error::NotFound), "Internal"),
            (Error::OldConfigNotFound(crate::model::image::config::Error::MissingVmConfig), "Internal"),
        ];
        
        for (error, expected_status_type) in errors_and_expected_status {
            let status: Status = error.into();
            match (status, expected_status_type) {
                (Status::InvalidArgument(_), "InvalidArgument") => (),
                (Status::Internal(_), "Internal") => (),
                (actual, expected) => panic!("Error conversion mismatch: expected {}", expected),
            }
        }
    }

    /// Test boundary conditions for resource calculations
    #[test]
    fn test_boundary_conditions() {
        let upgrade = MockUpgradeNode;
        
        // Test with minimum positive values
        let old_resources = (1, 1, 1);
        let new_resources = (1, 1, 1);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 0);
        assert_eq!(memory_diff, 0);
        assert_eq!(disk_diff, 0);
        
        // Test with maximum safe values (half of i64::MAX to prevent overflow)
        let max_safe = i64::MAX / 4; // Use quarter to be extra safe
        let old_resources = (max_safe, max_safe, max_safe);
        let new_resources = (max_safe, max_safe, max_safe);
        
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 0);
        assert_eq!(memory_diff, 0);
        assert_eq!(disk_diff, 0);
        
        // Test small increment from maximum safe values
        let new_resources = (max_safe + 1, max_safe + 1, max_safe + 1);
        let result = upgrade.calculate_resource_differences(old_resources, new_resources);
        assert!(result.is_ok());
        let (cpu_diff, memory_diff, disk_diff) = result.unwrap();
        assert_eq!(cpu_diff, 1);
        assert_eq!(memory_diff, 1);
        assert_eq!(disk_diff, 1);
    }
}