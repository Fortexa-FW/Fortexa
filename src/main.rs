mod rules;
mod api;
mod firewall;
mod firewall_daemon;

use std::sync::Arc;
use tokio::sync::Mutex;
use crate::{
    rules::FirewallRuleSet,
    firewall::iptables::FirewallManager,
};
use log::{info, error, debug, warn};

const RULES_FILE: &str = "rules.json";

#[tokio::main]
async fn main() {
    env_logger::init();
    let _firewall = FirewallManager::new();

    // Load or initialize rules
    let rules = FirewallRuleSet::load_from_file(RULES_FILE);
    

    // Apply initial rules to kernel
    if let Err(e) = FirewallManager::sync_rules(&rules) {
        error!("Failed to sync rules on startup: {}", e);
        std::process::exit(1);
    }

    // Share rules between components
    let rules = Arc::new(Mutex::new(rules));

    // Start API server
    let api_rules = rules.clone();
    let api_handle = tokio::spawn(async move {
        api::api_server::run(api_rules).await;
    });

    // Start firewall daemon (for logging)
    let daemon_rules = rules.clone();
    let daemon_handle = tokio::task::spawn_blocking(move || {
        firewall_daemon::firewall_daemon::run(daemon_rules);
    });

    // Wait for both to finish (they won't unless error)
    let _ = tokio::join!(api_handle, daemon_handle);
}
