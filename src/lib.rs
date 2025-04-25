pub mod api;
pub mod firewall;
pub mod firewall_daemon;
pub mod rules;

use crate::{firewall::iptables::{FirewallError, FirewallManager, IPTablesInterface, IPTablesWrapper},rules::FirewallRuleSet};
use log::error; // info, error, debug, warn if needed
use std::sync::Arc;
use tokio::sync::Mutex;

pub const RULES_FILE: &str = "rules.json";

pub async fn run() -> Result<(), FirewallError> {
    env_logger::init();

    let ipt = IPTablesWrapper::new(false)  
        .map_err(|e| FirewallError::ChainError(format!("Wrapper init: {}", e)))?; 

    // 1. Initialize firewall manager
    let firewall = FirewallManager::new("filter", false, ipt).unwrap_or_else(|e| {
        error!("Failed to initialize firewall: {}", e);
        std::process::exit(1);
    });

    // 2. Load rules from file
    let rules = FirewallRuleSet::load_from_file(RULES_FILE);

    // 3. Sync initial rules to kernel
    firewall.sync_rules(&rules).unwrap_or_else(|e| {
        error!("Failed to sync initial rules: {}", e);
        std::process::exit(1);
    });

    // 4. Prepare shared state for async tasks
    let firewall = Arc::new(tokio::sync::Mutex::new(firewall));  
    let rules = Arc::new(Mutex::new(rules));

    // 5. Start API server
    let api_firewall = Arc::clone(&firewall);
    let api_rules = Arc::clone(&rules);

    let api_router = api::api_server::router(
        api_firewall,
        api_rules
    );

    let api_handle = tokio::spawn(async move {
        api::api_server::run(api_router).await;
    });

    // 6. Start firewall daemon (for logging)
    let daemon_handle = {
        let rules = Arc::clone(&rules);
        tokio::task::spawn_blocking(move || {
            firewall_daemon::core::run(rules);
        })
    };

    // 7. Wait for tasks (they'll run indefinitely unless errors)
    let _ = tokio::join!(api_handle, daemon_handle);
    Ok(())
}
