use std::collections::HashMap;

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use displaydoc::Display;
use thiserror::Error;
use tracing::{error, info, warn};

use crate::auth::resource::{HostId, NodeId};
use crate::database::Conn;
use crate::model::image::Config;
use crate::model::schema::{configs, hosts, nodes};
use crate::model::{Host, Node};

#[derive(Debug, Display, Error)]
pub enum ValidationError {
    /// Failed to query nodes for validation: {0}
    QueryNodes(diesel::result::Error),
    /// Failed to query hosts for validation: {0}
    QueryHosts(diesel::result::Error),
    /// Failed to query configs for validation: {0}
    QueryConfigs(diesel::result::Error),
    /// Failed to parse node config: {0}
    ParseNodeConfig(crate::model::image::config::Error),
    /// Failed to update node resource fields: {0}
    UpdateNodeResources(diesel::result::Error),
    /// Failed to update host resource counters: {0}
    UpdateHostCounters(diesel::result::Error),
}

/// Represents a node resource inconsistency
#[derive(Debug, Clone)]
pub struct NodeResourceInconsistency {
    pub node_id: NodeId,
    pub node_name: String,
    pub stored_cpu_cores: i64,
    pub stored_memory_bytes: i64,
    pub stored_disk_bytes: i64,
    pub config_cpu_cores: i64,
    pub config_memory_bytes: i64,
    pub config_disk_bytes: i64,
}

/// Represents a host counter inconsistency
#[derive(Debug, Clone)]
pub struct HostCounterInconsistency {
    pub host_id: HostId,
    pub host_name: String,
    pub stored_cpu_cores: i64,
    pub stored_memory_bytes: i64,
    pub stored_disk_bytes: i64,
    pub actual_cpu_cores: i64,
    pub actual_memory_bytes: i64,
    pub actual_disk_bytes: i64,
}

/// Results of resource tracking validation
#[derive(Debug, Clone)]
pub struct ValidationResults {
    pub node_inconsistencies: Vec<NodeResourceInconsistency>,
    pub host_inconsistencies: Vec<HostCounterInconsistency>,
    pub total_nodes_checked: usize,
    pub total_hosts_checked: usize,
}

impl ValidationResults {
    pub fn has_inconsistencies(&self) -> bool {
        !self.node_inconsistencies.is_empty() || !self.host_inconsistencies.is_empty()
    }

    pub fn log_summary(&self) {
        if self.has_inconsistencies() {
            error!(
                "Resource tracking validation found {} node inconsistencies and {} host inconsistencies",
                self.node_inconsistencies.len(),
                self.host_inconsistencies.len()
            );
            
            for inconsistency in &self.node_inconsistencies {
                warn!(
                    "Node {} ({}) has resource mismatch: stored=({},{},{}) vs config=({},{},{})",
                    inconsistency.node_id,
                    inconsistency.node_name,
                    inconsistency.stored_cpu_cores,
                    inconsistency.stored_memory_bytes,
                    inconsistency.stored_disk_bytes,
                    inconsistency.config_cpu_cores,
                    inconsistency.config_memory_bytes,
                    inconsistency.config_disk_bytes
                );
            }
            
            for inconsistency in &self.host_inconsistencies {
                warn!(
                    "Host {} ({}) has counter mismatch: stored=({},{},{}) vs actual=({},{},{})",
                    inconsistency.host_id,
                    inconsistency.host_name,
                    inconsistency.stored_cpu_cores,
                    inconsistency.stored_memory_bytes,
                    inconsistency.stored_disk_bytes,
                    inconsistency.actual_cpu_cores,
                    inconsistency.actual_memory_bytes,
                    inconsistency.actual_disk_bytes
                );
            }
        } else {
            info!(
                "Resource tracking validation passed: {} nodes and {} hosts checked, no inconsistencies found",
                self.total_nodes_checked,
                self.total_hosts_checked
            );
        }
    }
}

/// Validates that node resource fields match their configurations
pub async fn validate_node_resource_consistency(
    conn: &mut Conn<'_>,
) -> Result<Vec<NodeResourceInconsistency>, ValidationError> {
    info!("Starting node resource consistency validation");
    
    // Query all active nodes with their configs
    let nodes_with_configs: Vec<(Node, Config)> = nodes::table
        .inner_join(configs::table.on(nodes::config_id.eq(configs::id)))
        .filter(nodes::deleted_at.is_null())
        .select((Node::as_select(), configs::all_columns))
        .get_results(conn)
        .await
        .map_err(ValidationError::QueryNodes)?;

    let mut inconsistencies = Vec::new();

    let total_nodes = nodes_with_configs.len();
    
    for (node, config) in nodes_with_configs {
        // Parse the node config to get resource requirements
        let node_config = config
            .node_config()
            .map_err(ValidationError::ParseNodeConfig)?;

        let config_cpu_cores = i64::try_from(node_config.vm.cpu_cores)
            .unwrap_or_else(|_| {
                warn!("Failed to convert CPU cores for node {}: using stored value", node.id);
                node.cpu_cores
            });
        let config_memory_bytes = i64::try_from(node_config.vm.memory_bytes)
            .unwrap_or_else(|_| {
                warn!("Failed to convert memory bytes for node {}: using stored value", node.id);
                node.memory_bytes
            });
        let config_disk_bytes = i64::try_from(node_config.vm.disk_bytes)
            .unwrap_or_else(|_| {
                warn!("Failed to convert disk bytes for node {}: using stored value", node.id);
                node.disk_bytes
            });

        // Check if stored values match config values
        if node.cpu_cores != config_cpu_cores
            || node.memory_bytes != config_memory_bytes
            || node.disk_bytes != config_disk_bytes
        {
            inconsistencies.push(NodeResourceInconsistency {
                node_id: node.id,
                node_name: node.node_name.clone(),
                stored_cpu_cores: node.cpu_cores,
                stored_memory_bytes: node.memory_bytes,
                stored_disk_bytes: node.disk_bytes,
                config_cpu_cores,
                config_memory_bytes,
                config_disk_bytes,
            });
        }
    }

    info!(
        "Node resource consistency validation completed: {} inconsistencies found out of {} nodes",
        inconsistencies.len(),
        total_nodes
    );

    Ok(inconsistencies)
}

/// Validates that host resource counters match the sum of node allocations
pub async fn validate_host_counter_consistency(
    conn: &mut Conn<'_>,
) -> Result<Vec<HostCounterInconsistency>, ValidationError> {
    info!("Starting host counter consistency validation");
    
    // Query all active hosts
    let hosts: Vec<Host> = hosts::table
        .filter(hosts::deleted_at.is_null())
        .get_results(conn)
        .await
        .map_err(ValidationError::QueryHosts)?;

    // Query all active nodes grouped by host
    let nodes: Vec<Node> = nodes::table
        .filter(nodes::deleted_at.is_null())
        .get_results(conn)
        .await
        .map_err(ValidationError::QueryNodes)?;

    // Group nodes by host_id and calculate actual resource usage
    let mut host_actual_resources: HashMap<HostId, (i64, i64, i64)> = HashMap::new();
    for node in nodes {
        let entry = host_actual_resources
            .entry(node.host_id)
            .or_insert((0, 0, 0));
        entry.0 += node.cpu_cores;
        entry.1 += node.memory_bytes;
        entry.2 += node.disk_bytes;
    }

    let mut inconsistencies = Vec::new();

    for host in &hosts {
        let (actual_cpu, actual_memory, actual_disk) = host_actual_resources
            .get(&host.id)
            .copied()
            .unwrap_or((0, 0, 0));

        // Check if stored counters match actual sums
        if host.node_cpu_cores != actual_cpu
            || host.node_memory_bytes != actual_memory
            || host.node_disk_bytes != actual_disk
        {
            inconsistencies.push(HostCounterInconsistency {
                host_id: host.id,
                host_name: host.network_name.clone(),
                stored_cpu_cores: host.node_cpu_cores,
                stored_memory_bytes: host.node_memory_bytes,
                stored_disk_bytes: host.node_disk_bytes,
                actual_cpu_cores: actual_cpu,
                actual_memory_bytes: actual_memory,
                actual_disk_bytes: actual_disk,
            });
        }
    }

    info!(
        "Host counter consistency validation completed: {} inconsistencies found out of {} hosts",
        inconsistencies.len(),
        hosts.len()
    );

    Ok(inconsistencies)
}

/// Performs comprehensive resource tracking validation
pub async fn validate_resource_tracking_consistency(
    conn: &mut Conn<'_>,
) -> Result<ValidationResults, ValidationError> {
    info!("Starting comprehensive resource tracking validation");
    
    let node_inconsistencies = validate_node_resource_consistency(conn).await?;
    let host_inconsistencies = validate_host_counter_consistency(conn).await?;

    // Count total nodes and hosts checked
    let total_nodes_checked = nodes::table
        .filter(nodes::deleted_at.is_null())
        .count()
        .get_result::<i64>(conn)
        .await
        .map_err(ValidationError::QueryNodes)? as usize;

    let total_hosts_checked = hosts::table
        .filter(hosts::deleted_at.is_null())
        .count()
        .get_result::<i64>(conn)
        .await
        .map_err(ValidationError::QueryHosts)? as usize;

    let results = ValidationResults {
        node_inconsistencies,
        host_inconsistencies,
        total_nodes_checked,
        total_hosts_checked,
    };

    results.log_summary();
    
    Ok(results)
}

/// Repairs node resource field inconsistencies by updating them to match their configs
pub async fn repair_node_resource_inconsistencies(
    inconsistencies: &[NodeResourceInconsistency],
    conn: &mut Conn<'_>,
) -> Result<usize, ValidationError> {
    if inconsistencies.is_empty() {
        info!("No node resource inconsistencies to repair");
        return Ok(0);
    }

    info!("Repairing {} node resource inconsistencies", inconsistencies.len());
    
    let mut repaired_count = 0;

    for inconsistency in inconsistencies {
        let result = diesel::update(nodes::table.find(inconsistency.node_id))
            .set((
                nodes::cpu_cores.eq(inconsistency.config_cpu_cores),
                nodes::memory_bytes.eq(inconsistency.config_memory_bytes),
                nodes::disk_bytes.eq(inconsistency.config_disk_bytes),
            ))
            .execute(conn)
            .await;

        match result {
            Ok(1) => {
                info!(
                    "Repaired node {} ({}): updated resources to ({},{},{})",
                    inconsistency.node_id,
                    inconsistency.node_name,
                    inconsistency.config_cpu_cores,
                    inconsistency.config_memory_bytes,
                    inconsistency.config_disk_bytes
                );
                repaired_count += 1;
            }
            Ok(0) => {
                warn!(
                    "Node {} ({}) not found during repair - may have been deleted",
                    inconsistency.node_id, inconsistency.node_name
                );
            }
            Ok(n) => {
                error!(
                    "Unexpected number of rows ({}) updated for node {} ({})",
                    n, inconsistency.node_id, inconsistency.node_name
                );
            }
            Err(err) => {
                error!(
                    "Failed to repair node {} ({}): {}",
                    inconsistency.node_id, inconsistency.node_name, err
                );
                return Err(ValidationError::UpdateNodeResources(err));
            }
        }
    }

    info!("Successfully repaired {} node resource inconsistencies", repaired_count);
    Ok(repaired_count)
}

/// Repairs host counter inconsistencies by recalculating them from actual node allocations
pub async fn repair_host_counter_inconsistencies(
    inconsistencies: &[HostCounterInconsistency],
    conn: &mut Conn<'_>,
) -> Result<usize, ValidationError> {
    if inconsistencies.is_empty() {
        info!("No host counter inconsistencies to repair");
        return Ok(0);
    }

    info!("Repairing {} host counter inconsistencies", inconsistencies.len());
    
    let mut repaired_count = 0;

    for inconsistency in inconsistencies {
        let result = diesel::update(hosts::table.find(inconsistency.host_id))
            .set((
                hosts::node_cpu_cores.eq(inconsistency.actual_cpu_cores),
                hosts::node_memory_bytes.eq(inconsistency.actual_memory_bytes),
                hosts::node_disk_bytes.eq(inconsistency.actual_disk_bytes),
            ))
            .execute(conn)
            .await;

        match result {
            Ok(1) => {
                info!(
                    "Repaired host {} ({}): updated counters to ({},{},{})",
                    inconsistency.host_id,
                    inconsistency.host_name,
                    inconsistency.actual_cpu_cores,
                    inconsistency.actual_memory_bytes,
                    inconsistency.actual_disk_bytes
                );
                repaired_count += 1;
            }
            Ok(0) => {
                warn!(
                    "Host {} ({}) not found during repair - may have been deleted",
                    inconsistency.host_id, inconsistency.host_name
                );
            }
            Ok(n) => {
                error!(
                    "Unexpected number of rows ({}) updated for host {} ({})",
                    n, inconsistency.host_id, inconsistency.host_name
                );
            }
            Err(err) => {
                error!(
                    "Failed to repair host {} ({}): {}",
                    inconsistency.host_id, inconsistency.host_name, err
                );
                return Err(ValidationError::UpdateHostCounters(err));
            }
        }
    }

    info!("Successfully repaired {} host counter inconsistencies", repaired_count);
    Ok(repaired_count)
}

/// Performs comprehensive repair of all resource tracking inconsistencies
pub async fn repair_all_resource_inconsistencies(
    conn: &mut Conn<'_>,
) -> Result<(usize, usize), ValidationError> {
    info!("Starting comprehensive resource tracking repair");
    
    let validation_results = validate_resource_tracking_consistency(conn).await?;
    
    if !validation_results.has_inconsistencies() {
        info!("No resource tracking inconsistencies found - no repairs needed");
        return Ok((0, 0));
    }

    let nodes_repaired = repair_node_resource_inconsistencies(
        &validation_results.node_inconsistencies,
        conn,
    ).await?;

    let hosts_repaired = repair_host_counter_inconsistencies(
        &validation_results.host_inconsistencies,
        conn,
    ).await?;

    info!(
        "Resource tracking repair completed: {} nodes and {} hosts repaired",
        nodes_repaired, hosts_repaired
    );

    Ok((nodes_repaired, hosts_repaired))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::tests::TestDb;
    use crate::config::Config;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_validate_node_resource_consistency() {
        let config = Config::from_default_toml().expect("should load config");
        let mut rng = OsRng;
        let test_db = TestDb::new(&config.database, &mut rng).await;
        let mut conn = test_db.conn().await;

        // Test with clean database - should find no inconsistencies
        let inconsistencies = validate_node_resource_consistency(&mut conn)
            .await
            .expect("validation should succeed");
        
        assert!(inconsistencies.is_empty(), "Clean database should have no inconsistencies");
    }

    #[tokio::test]
    async fn test_validate_host_counter_consistency() {
        let config = Config::from_default_toml().expect("should load config");
        let mut rng = OsRng;
        let test_db = TestDb::new(&config.database, &mut rng).await;
        let mut conn = test_db.conn().await;

        // Test with clean database - should find no inconsistencies
        let inconsistencies = validate_host_counter_consistency(&mut conn)
            .await
            .expect("validation should succeed");
        
        assert!(inconsistencies.is_empty(), "Clean database should have no inconsistencies");
    }

    #[tokio::test]
    async fn test_comprehensive_validation() {
        let config = Config::from_default_toml().expect("should load config");
        let mut rng = OsRng;
        let test_db = TestDb::new(&config.database, &mut rng).await;
        let mut conn = test_db.conn().await;

        // Test comprehensive validation
        let results = validate_resource_tracking_consistency(&mut conn)
            .await
            .expect("validation should succeed");
        
        assert!(!results.has_inconsistencies(), "Clean database should have no inconsistencies");
        assert!(results.total_nodes_checked >= 0);
        assert!(results.total_hosts_checked >= 0);
    }
}