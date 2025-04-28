pub mod api;
pub mod firewall;
pub mod firewall_daemon;

use crate::{
    firewall::core::FirewallManager, firewall::error::FirewallError,
    firewall::iptables::iptables_impl::IPTablesInterface, firewall::rules_core::RulesManager,
};
use firewall::IPTablesWrapper;
use log::error; // info, error, debug, warn if needed
use std::sync::Arc;
use tokio::sync::Mutex;

pub static RULES_FILE: &str = match option_env!("RULES_FILE") {
    Some(path) => path,
    None => "rules.json",
};

pub async fn run() -> Result<(), FirewallError> {
    env_logger::init();

    // 1. Initialize firewall manager
    let mut firewall = FirewallManager::new().unwrap_or_else(|e| {
        error!("Failed to initialize firewall: {}", e);
        std::process::exit(1);
    });

    // 2. Load rules from file
    let rules = RulesManager::new().unwrap_or_else(|e| {
        error!("Failed to initialize firewall rules manager: {}", e);
        std::process::exit(1);
    });

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

    let api_router = api::api_server::router(api_firewall, api_rules);

    let api_handle = tokio::spawn(async move {
        api::api_server::run::<IPTablesWrapper>(api_router.await)
            .await
            .unwrap_or_else(|e| {
                error!("Failed to run API server: {}", e);
                std::process::exit(1);
            });
    });

    // 6. Start firewall daemon (for logging)
    let daemon_handle = {
        let rules = Arc::clone(&rules);
        tokio::spawn(async move {
            firewall_daemon::core::FirewallDaemon::new(rules).await;
        })
    };

    // 7. Wait for tasks (they'll run indefinitely unless errors)
    let _ = tokio::join!(api_handle, daemon_handle);
    Ok(())
}
