use serde::Deserialize;
use std::collections::HashMap;

use crate::grpc::api;

#[derive(Debug, Deserialize)]
pub struct BabelConfig {
    pub data_directory_mount_point: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BlockchainMetadata {
    pub requirements: HardwareRequirements,
    pub nets: HashMap<String, NetConfiguration>,
    pub babel_config: Option<BabelConfig>,
}

#[derive(Debug, Deserialize)]
pub struct HardwareRequirements {
    pub vcpu_count: u64,
    pub mem_size_mb: u64,
    pub disk_size_gb: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetType {
    Dev,
    Test,
    Main,
}

#[derive(Debug, Deserialize)]
pub struct NetConfiguration {
    pub url: String,
    pub net_type: NetType,
    #[serde(flatten)]
    pub meta: HashMap<String, String>,
}

impl From<NetType> for api::NetType {
    fn from(value: NetType) -> Self {
        match value {
            NetType::Test => api::NetType::Test,
            NetType::Main => api::NetType::Main,
            NetType::Dev => api::NetType::Dev,
        }
    }
}

#[cfg(any(test, feature = "integration-test"))]
#[allow(unused_imports)]
pub mod tests {
    use crate::cookbook::Cookbook;

    use super::*;

    pub const TEST_SCRIPT: &str = r#"
        const METADATA = #{
            // comments are allowed
            min_babel_version: "0.0.9",
            node_version: "node_v",
            protocol: "proto",
            node_type: "n_type",
            description: "node description",
            requirements: #{
                vcpu_count: 1,
                mem_size_mb: 8192,
                disk_size_gb: 10,
                more: 0,
            },
            nets: #{
                mainnet: #{
                    url: "https://rpc.ankr.com/eth",
                    net_type: "main",
                    beacon_nodes_csv: "http://beacon01.mainnet.eth.blockjoy.com,http://beacon02.mainnet.eth.blockjoy.com?123",
                    param_a: "value_a",
                },
                sepolia: #{
                    url: "https://rpc.sepolia.dev",
                    net_type: "test",
                    beacon_nodes_csv: "http://beacon01.sepolia.eth.blockjoy.com,http://beacon02.sepolia.eth.blockjoy.com?456",
                    param_b: "value_b",
                },
                goerli: #{
                    url: "https://goerli.prylabs.net",
                    net_type: "test",
                    beacon_nodes_csv: "http://beacon01.goerli.eth.blockjoy.com,http://beacon02.goerli.eth.blockjoy.com?789",
                    param_c: "value_c",
                },
            },
            babel_config: #{
                data_directory_mount_point: "/mnt/data/",
                log_buffer_capacity_ln: 1024,
                swap_size_mb: 1024,
            },
            firewall: #{
                enabled: true,
                default_in: "deny",
                default_out: "allow",
                rules: [
                    #{
                        name: "Rule A",
                        action: "allow",
                        direction: "in",
                        protocol: "tcp",
                        ips: "192.168.0.1/24",
                        ports: [77, 1444, 8080],
                    },
                    #{
                        name: "Rule B",
                        action: "deny",
                        direction: "out",
                        protocol: "udp",
                        ips: "192.167.0.1/24",
                        ports: [77],
                    },
                    #{
                        name: "Rule C",
                        action: "reject",
                        direction: "out",
                        ips: "192.169.0.1/24",
                        ports: [],
                    },
                ],
            },
            keys: #{
                key_a_name: "key A Value",
                key_B_name: "key B Value",
                key_X_name: "X",
                "*": "/*"
            },
        };
        fn some_function() {}
    "#;

    #[test]
    fn can_deserialize_rhai() {
        let engine = rhai::Engine::new();
        let config = Cookbook::script_to_metadata(&engine, TEST_SCRIPT, "test").unwrap();

        assert_eq!(config.requirements.vcpu_count, 1);
        assert_eq!(config.requirements.mem_size_mb, 8192);
        assert_eq!(config.requirements.disk_size_gb, 10);

        let mainnet = config.nets.get("mainnet").unwrap();
        let sepolia = config.nets.get("sepolia").unwrap();
        let goerli = config.nets.get("goerli").unwrap();

        assert_eq!(mainnet.net_type, NetType::Main);
        assert_eq!(sepolia.net_type, NetType::Test);
        assert_eq!(goerli.net_type, NetType::Test);

        assert_eq!(mainnet.url, "https://rpc.ankr.com/eth");
        assert_eq!(sepolia.url, "https://rpc.sepolia.dev");
        assert_eq!(goerli.url, "https://goerli.prylabs.net");

        assert_eq!(
            mainnet.meta.get("beacon_nodes_csv").unwrap(),
            "http://beacon01.mainnet.eth.blockjoy.com,http://beacon02.mainnet.eth.blockjoy.com?123"
        );
        assert_eq!(
            sepolia.meta.get("beacon_nodes_csv").unwrap(),
            "http://beacon01.sepolia.eth.blockjoy.com,http://beacon02.sepolia.eth.blockjoy.com?456"
        );
        assert_eq!(
            goerli.meta.get("beacon_nodes_csv").unwrap(),
            "http://beacon01.goerli.eth.blockjoy.com,http://beacon02.goerli.eth.blockjoy.com?789"
        );

        assert_eq!(mainnet.meta.get("param_a").unwrap(), "value_a");
        assert_eq!(sepolia.meta.get("param_b").unwrap(), "value_b");
        assert_eq!(goerli.meta.get("param_c").unwrap(), "value_c");
    }
}
