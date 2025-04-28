use crate::{
    RULES_FILE, firewall::iptables::iptables_impl,
    firewall::iptables::iptables_impl::IPTablesInterface,
    firewall::iptables::iptables_manager::IPTablesManager,
    firewall::iptables::rules::IPTablesRuleSet,
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{delete, get, post},
};
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct IPTablesAppState<T: IPTablesInterface + Send + Sync + 'static> {
    iptables_mgr: Arc<Mutex<IPTablesManager<T>>>,
    rules: Arc<Mutex<IPTablesRuleSet>>,
}

impl<T: IPTablesInterface + Send + Sync + 'static> Clone for IPTablesAppState<T> {
    fn clone(&self) -> Self {
        Self {
            iptables_mgr: self.iptables_mgr.clone(),
            rules: self.rules.clone(),
        }
    }
}

// For full rule replacement
#[derive(Debug, serde::Deserialize)]
pub struct IPTablesRuleSetUpdate {
    #[serde(default)]
    pub input: IPTablesDirectionRulesUpdate,
    #[serde(default)]
    pub output: IPTablesDirectionRulesUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IPTablesDirectionRulesUpdate {
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

pub fn iptables_router<T: iptables_impl::IPTablesInterface + 'static>(
    iptables_mgr: Arc<Mutex<IPTablesManager<T>>>,
    rules: Arc<Mutex<IPTablesRuleSet>>,
) -> Router {
    let state = IPTablesAppState {
        iptables_mgr,
        rules,
    };

    Router::new()
        .route(
            "/iptables/rules",
            get(get_rules::<T>).post(replace_rules::<T>),
        )
        .route("/iptables/rules/append", post(append_rules::<T>))
        .route("/iptables/rules/delete", delete(delete_rules::<T>))
        .route("/iptables/rules/reset", post(reset_iptables_rules::<T>))
        .with_state(state)
}

// GET handler for rules endpoint
async fn get_rules<T: IPTablesInterface + Send + Sync + 'static>(
    State(state): State<IPTablesAppState<T>>,
) -> Json<IPTablesRuleSet> {
    let rules = state.rules.lock().await;
    Json(rules.clone())
}

// Full rule replacement (original behavior)
async fn replace_rules<T: IPTablesInterface + Send + Sync + 'static>(
    State(state): State<IPTablesAppState<T>>,
    Json(new_rules): Json<IPTablesRuleSet>,
) -> Json<&'static str> {
    let mut current_rules = state.rules.lock().await;
    *current_rules = new_rules;

    let iptables_mgr = state.iptables_mgr.lock().await;
    iptables_mgr
        .sync_rules(&current_rules)
        .expect("Failed to sync iptables rules");

    current_rules.save_to_file(RULES_FILE);
    Json("Rules fully replaced and saved")
}

// Append rules (partial update)
async fn append_rules<T: IPTablesInterface + Send + Sync + 'static>(
    State(state): State<IPTablesAppState<T>>,
    Json(update): Json<IPTablesRuleSetUpdate>,
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

    let iptables_mgr = state.iptables_mgr.lock().await;
    iptables_mgr
        .sync_rules(&current_rules)
        .expect("Failed to sync iptables rules");

    current_rules.save_to_file(RULES_FILE);
    Json("Rules appended successfully")
}

// Delete rules (partial update)
async fn delete_rules<T: IPTablesInterface + Send + Sync>(
    State(state): State<IPTablesAppState<T>>,
    Json(delete_request): Json<DeleteRulesRequest>,
) -> Result<Json<&'static str>, (StatusCode, String)> {
    // Lock both resources upfront
    let mut current_rules = state.rules.lock().await;
    let iptables_mgr = state.iptables_mgr.lock().await;

    // Remove input rules
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

    // Remove output rules
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
    iptables_mgr.sync_rules(&current_rules).map_err(|e| {
        let msg = format!("Failed to sync rules: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, msg)
    })?;

    // Persist rules
    current_rules.save_to_file(RULES_FILE);

    Ok(Json("Rules deleted successfully"))
}

async fn reset_iptables_rules<T: IPTablesInterface + Send + Sync + 'static>(
    State(state): State<IPTablesAppState<T>>,
) -> Json<&'static str> {
    let iptables_mgr = state.iptables_mgr.lock().await;
    iptables_mgr
        .delete_rules()
        .expect("Failed to delete all rules");
    Json("All iptables rules deleted")
}
