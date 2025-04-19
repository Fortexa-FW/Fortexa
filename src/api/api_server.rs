use axum::{
    extract::State,
    routing::{get, post},
    Router, Json,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::{
    rules::FirewallRuleSet,
    firewall::iptables::FirewallManager,
};

const RULES_FILE: &str = "rules.json";

pub async fn run(rules: Arc<Mutex<FirewallRuleSet>>) {
    let app = Router::new()
        .route("/rules", get(get_rules).post(post_rules))
        .with_state(rules);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    println!("API server listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_rules(State(rules): State<Arc<Mutex<FirewallRuleSet>>>) -> Json<FirewallRuleSet> {
    let rules = rules.lock().await;
    Json(rules.clone())
}

async fn post_rules(
    State(rules): State<Arc<Mutex<FirewallRuleSet>>>,
    Json(new_rules): Json<FirewallRuleSet>,
) -> Json<&'static str> {
    let mut current_rules = rules.lock().await;
    *current_rules = new_rules;

    FirewallManager::sync_rules(&current_rules)
        .expect("Failed to sync firewall rules");
    current_rules.save_to_file(RULES_FILE);

    Json("Rules updated and saved")
}
