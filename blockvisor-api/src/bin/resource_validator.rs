use std::process;

use clap::{Parser, Subcommand};
use tracing::{error, info};

use blockvisor_api::config::Context;
use blockvisor_api::database::validation::{
    repair_all_resource_inconsistencies, validate_resource_tracking_consistency,
};
use blockvisor_api::database::Database;

#[derive(Parser)]
#[command(name = "resource-validator")]
#[command(about = "A utility for validating and repairing resource tracking consistency")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate resource tracking consistency without making changes
    Validate,
    /// Repair all resource tracking inconsistencies
    Repair {
        /// Actually perform the repairs (dry-run by default)
        #[arg(long)]
        apply: bool,
    },
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Load configuration
    let ctx = match Context::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            process::exit(1);
        }
    };

    // Get database connection
    let mut conn = match ctx.conn().await {
        Ok(conn) => conn,
        Err(err) => {
            error!("Failed to connect to database: {}", err);
            process::exit(1);
        }
    };

    let result = match cli.command {
        Commands::Validate => validate_command(&mut conn).await,
        Commands::Repair { apply } => repair_command(&mut conn, apply).await,
    };

    if let Err(err) = result {
        error!("Command failed: {}", err);
        process::exit(1);
    }
}

async fn validate_command(
    conn: &mut blockvisor_api::database::Conn<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Running resource tracking validation...");

    let results = validate_resource_tracking_consistency(conn).await?;

    if results.has_inconsistencies() {
        println!("\n=== VALIDATION RESULTS ===");
        println!(
            "Found {} node inconsistencies and {} host inconsistencies",
            results.node_inconsistencies.len(),
            results.host_inconsistencies.len()
        );

        if !results.node_inconsistencies.is_empty() {
            println!("\nNode Resource Inconsistencies:");
            for inconsistency in &results.node_inconsistencies {
                println!(
                    "  Node {} ({}): stored=({},{},{}) vs config=({},{},{})",
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
        }

        if !results.host_inconsistencies.is_empty() {
            println!("\nHost Counter Inconsistencies:");
            for inconsistency in &results.host_inconsistencies {
                println!(
                    "  Host {} ({}): stored=({},{},{}) vs actual=({},{},{})",
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
        }

        println!("\nTo fix these inconsistencies, run:");
        println!("  resource-validator repair --apply");
        
        process::exit(1);
    } else {
        println!("✅ All resource tracking is consistent!");
        println!(
            "Checked {} nodes and {} hosts - no inconsistencies found.",
            results.total_nodes_checked, results.total_hosts_checked
        );
    }

    Ok(())
}

async fn repair_command(
    conn: &mut blockvisor_api::database::Conn<'_>,
    apply: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if apply {
        info!("Running resource tracking repair with changes applied...");
        
        let (nodes_repaired, hosts_repaired) = repair_all_resource_inconsistencies(conn).await?;
        
        println!("\n=== REPAIR RESULTS ===");
        println!("Successfully repaired:");
        println!("  {} node resource inconsistencies", nodes_repaired);
        println!("  {} host counter inconsistencies", hosts_repaired);
        
        if nodes_repaired > 0 || hosts_repaired > 0 {
            println!("\n✅ Resource tracking inconsistencies have been fixed!");
        } else {
            println!("\n✅ No inconsistencies found - database is already consistent!");
        }
    } else {
        info!("Running resource tracking repair in dry-run mode...");
        
        let results = validate_resource_tracking_consistency(conn).await?;
        
        println!("\n=== DRY RUN RESULTS ===");
        if results.has_inconsistencies() {
            println!("Would repair:");
            println!("  {} node resource inconsistencies", results.node_inconsistencies.len());
            println!("  {} host counter inconsistencies", results.host_inconsistencies.len());
            println!("\nTo actually apply these repairs, run:");
            println!("  resource-validator repair --apply");
        } else {
            println!("✅ No inconsistencies found - no repairs needed!");
        }
    }

    Ok(())
}