use axum::{
    extract::State,
    routing::{get, post, delete},
    Router, Json,
};
use std::sync::Arc;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio::sync::Mutex;
use crate::{
    rules::FirewallRuleSet,
    firewall::iptables::FirewallManager,
};

#[derive(Clone)]
struct AppState {
    firewall: Arc<Mutex<FirewallManager>>,
    rules: Arc<Mutex<FirewallRuleSet>>,
}

// DELETE Request on API
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
    pub blocked_ips: HashSet<Ipv4Addr>,
    #[serde(default)]
    pub blocked_ports: HashSet<u16>,
    #[serde(default)]
    pub whitelisted_ips: HashSet<Ipv4Addr>,
    #[serde(default)]
    pub whitelisted_ports: HashSet<u16>,
}


const RULES_FILE: &str = "rules.json";

pub async fn run(firewall: Arc<Mutex<FirewallManager>>, rules: Arc<Mutex<FirewallRuleSet>>) {
    let state = AppState { firewall, rules };

    let app = Router::new()
        .route("/rules", get(get_rules).post(post_rules))
        .with_state(state);


    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    println!("API server listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_rules(
    State(state): State<AppState>,
) -> Json<FirewallRuleSet> {
    let rules = state.rules.lock().await;
    Json(rules.clone())
}

async fn post_rules(
    State(state): State<AppState>,
    Json(new_rules): Json<FirewallRuleSet>,
) -> Json<&'static str> {
    // Update rules
    let mut current_rules = state.rules.lock().await;
    *current_rules = new_rules;

    // Sync to firewall
    let firewall = state.firewall.lock().await;
    firewall.sync_rules(&current_rules)
        .expect("Failed to sync firewall rules");

    current_rules.save_to_file(RULES_FILE);
    Json("Rules updated and saved")
}

async fn delete_rules(
    State(state): State<AppState>,
    Json(delete_request): Json<DeleteRulesRequest>,
) -> Json<&'static str> {
    let mut current_rules = state.rules.lock().await;

    // Remove specified input rules
    current_rules.input.blocked_ips.retain(|ip| !delete_request.input.blocked_ips.contains(ip));
    current_rules.input.blocked_ports.retain(|port| !delete_request.input.blocked_ports.contains(port));
    current_rules.input.whitelisted_ips.retain(|ip| !delete_request.input.whitelisted_ips.contains(ip));
    current_rules.input.whitelisted_ports.retain(|port| !delete_request.input.whitelisted_ports.contains(port));

    // Remove specified output rules
    current_rules.output.blocked_ips.retain(|ip| !delete_request.output.blocked_ips.contains(ip));
    current_rules.output.blocked_ports.retain(|port| !delete_request.output.blocked_ports.contains(port));
    current_rules.output.whitelisted_ips.retain(|ip| !delete_request.output.whitelisted_ips.contains(ip));
    current_rules.output.whitelisted_ports.retain(|port| !delete_request.output.whitelisted_ports.contains(port));

    // Sync with firewall
    let firewall = state.firewall.lock().await;
    firewall.sync_rules(&current_rules)
        .expect("Failed to sync rules after deletion");

    current_rules.save_to_file(RULES_FILE);

    Json("Specified rules deleted successfully")
}
