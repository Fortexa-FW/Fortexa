use crate::{firewall::iptables::FirewallManager,firewall::iptables::IPTablesInterface, firewall::iptables, rules::FirewallRuleSet };
use axum::{
    Json, Router,
    extract::State,
    routing::{delete, get, post},
};
use ipnetwork::Ipv4Network;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AppState<T: IPTablesInterface> {
    firewall: Arc<Mutex<FirewallManager<T>>>,
    rules: Arc<Mutex<FirewallRuleSet>>,
}

impl<T: IPTablesInterface> Clone for AppState<T> {
    fn clone(&self) -> Self {
        Self {
            firewall: self.firewall.clone(),
            rules: self.rules.clone(),
        }
    }
}

// For full rule replacement
#[derive(Debug, serde::Deserialize)]
pub struct FirewallRuleSetUpdate {
    #[serde(default)]
    pub input: FirewallDirectionRulesUpdate,
    #[serde(default)]
    pub output: FirewallDirectionRulesUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallDirectionRulesUpdate {
    #[serde(default)]
    pub blocked_ips: HashSet<Ipv4Network>,
    #[serde(default)]
    pub blocked_ports: HashSet<u16>,
    #[serde(default)]
    pub whitelisted_ips: HashSet<Ipv4Network>,
    #[serde(default)]
    pub whitelisted_ports: HashSet<u16>,
}

// DELETE Request structure
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct DeleteRulesRequest {
    #[serde(default)]
    pub input: DeleteDirectionRules,
    #[serde(default)]
    pub output: DeleteDirectionRules,
}

#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)]
pub struct DeleteDirectionRules {
    #[serde(default)]
    pub blocked_ips: HashSet<Ipv4Network>,
    #[serde(default)]
    pub blocked_ports: HashSet<u16>,
    #[serde(default)]
    pub whitelisted_ips: HashSet<Ipv4Network>,
    #[serde(default)]
    pub whitelisted_ports: HashSet<u16>,
}

const RULES_FILE: &str = "rules.json";

pub fn router(firewall: Arc<Mutex<FirewallManager>>, rules: Arc<Mutex<FirewallRuleSet>>) -> Router {
    let state = AppState { firewall, rules };

    return Router::new()
        .route("/rules", get(get_rules).post(replace_rules))
        .route("/rules/append", post(append_rules))
        .route("/rules/delete", delete(delete_rules))
        .route("/rules/reset", post(reset_iptables_rules))
        .with_state(state);
}

pub async fn run(router: Router) {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();
    debug!("API server listening on 0.0.0.0:3000");
}

// GET handler for rules endpoint
async fn get_rules<T: iptables::IPTablesInterface>(State(state): State<AppState<T>>) -> Json<FirewallRuleSet> {
    let rules = state.rules.lock().await;
    Json(rules.clone())
}

// Full rule replacement (original behavior)
async fn replace_rules<T: iptables::IPTablesInterface>(
    State(state): State<AppState<T>>,
    Json(new_rules): Json<FirewallRuleSet>,
) -> Json<&'static str> {
    let mut current_rules = state.rules.lock().await;
    *current_rules = new_rules;

    let firewall = state.firewall.lock().await;
    firewall
        .sync_rules(&current_rules)
        .expect("Failed to sync firewall rules");

    current_rules.save_to_file(RULES_FILE);
    Json("Rules fully replaced and saved")
}

// Append rules (partial update)
async fn append_rules<T: iptables::IPTablesInterface>(
    State(state): State<AppState<T>>,
    Json(update): Json<FirewallRuleSetUpdate>,
) -> Json<&'static str> {
    let mut current_rules = state.rules.lock().await;

    // Merge updates into existing rules
    current_rules
        .input
        .blocked_ips
        .extend(update.input.blocked_ips);
    current_rules
        .input
        .blocked_ports
        .extend(update.input.blocked_ports);
    current_rules
        .input
        .whitelisted_ips
        .extend(update.input.whitelisted_ips);
    current_rules
        .input
        .whitelisted_ports
        .extend(update.input.whitelisted_ports);

    current_rules
        .output
        .blocked_ips
        .extend(update.output.blocked_ips);
    current_rules
        .output
        .blocked_ports
        .extend(update.output.blocked_ports);
    current_rules
        .output
        .whitelisted_ips
        .extend(update.output.whitelisted_ips);
    current_rules
        .output
        .whitelisted_ports
        .extend(update.output.whitelisted_ports);

    let firewall = state.firewall.lock().await;
    firewall
        .sync_rules(&current_rules)
        .expect("Failed to sync firewall rules");

    current_rules.save_to_file(RULES_FILE);
    Json("Rules appended successfully")
}

// Delete rules (partial update)
async fn delete_rules<T: iptables::IPTablesInterface>(
    State(state): State<AppState<T>>,
    Json(delete_request): Json<DeleteRulesRequest>,
) -> Json<&'static str> {
    let mut current_rules = state.rules.lock().await;

    // Remove specified input rules
    current_rules
        .input
        .blocked_ips
        .retain(|ip| !delete_request.input.blocked_ips.contains(ip));
    current_rules
        .input
        .blocked_ports
        .retain(|port| !delete_request.input.blocked_ports.contains(port));
    current_rules
        .input
        .whitelisted_ips
        .retain(|ip| !delete_request.input.whitelisted_ips.contains(ip));
    current_rules
        .input
        .whitelisted_ports
        .retain(|port| !delete_request.input.whitelisted_ports.contains(port));

    // Remove specified output rules
    current_rules
        .output
        .blocked_ips
        .retain(|ip| !delete_request.output.blocked_ips.contains(ip));
    current_rules
        .output
        .blocked_ports
        .retain(|port| !delete_request.output.blocked_ports.contains(port));
    current_rules
        .output
        .whitelisted_ips
        .retain(|ip| !delete_request.output.whitelisted_ips.contains(ip));
    current_rules
        .output
        .whitelisted_ports
        .retain(|port| !delete_request.output.whitelisted_ports.contains(port));

    // Sync with firewall
    let firewall = state.firewall.lock().await;
    firewall
        .sync_rules(&current_rules)
        .expect("Failed to sync rules after deletion");

    current_rules.save_to_file(RULES_FILE);

    Json("Specified rules deleted successfully")
}

async fn reset_iptables_rules<T: iptables::IPTablesInterface>(State(state): State<AppState<T>>) -> Json<&'static str> {
    let firewall = state.firewall.lock().await;
    firewall.delete_rules().expect("Failed to delete all rules");
    Json("All firewall rules deleted")
}
