mod api;
mod firewall;
mod firewall_daemon;
mod rules;

use crate::{firewall::iptables::FirewallManager, rules::FirewallRuleSet};
use log::error; // info, error, debug, warn if needed
use std::sync::Arc;
use tokio::sync::Mutex;

const RULES_FILE: &str = "rules.json";

#[tokio::main]
async fn main() {
    env_logger::init();

    // 1. Initialize firewall manager
    let firewall = FirewallManager::new("filter", false)
        .unwrap_or_else(|e| {
            error!("Failed to initialize firewall: {}", e);
            std::process::exit(1);
        });

    // 2. Load rules from file
    let rules = FirewallRuleSet::load_from_file(RULES_FILE);

    // 3. Sync initial rules to kernel
    firewall.sync_rules(&rules)
        .unwrap_or_else(|e| {
            error!("Failed to sync initial rules: {}", e);
            std::process::exit(1);
        });

    // 4. Prepare shared state for async tasks
    let firewall = Arc::new(Mutex::new(firewall));
    let rules = Arc::new(Mutex::new(rules));

    // 5. Start API server
    let api_firewall = Arc::clone(&firewall);
    let api_rules = Arc::clone(&rules);
    let api_handle = tokio::spawn(async move {
        api::api_server::run(api_firewall, api_rules).await;
    });

    // 6. Start firewall daemon (for logging)
    let daemon_rules = Arc::clone(&rules);
    let daemon_handle = tokio::task::spawn_blocking(move || {
        firewall_daemon::firewall_daemon::run(daemon_rules);
    });

    // 7. Wait for tasks (they'll run indefinitely unless errors)
    let _ = tokio::join!(api_handle, daemon_handle);
}
