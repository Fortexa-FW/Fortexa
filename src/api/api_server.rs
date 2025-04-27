use crate::{firewall::core::FirewallManager, firewall::rules_core::RulesManager, firewall::iptables::rules::IPTablesRuleSet, api::iptables::api_iptables::iptables_router, IPTablesInterface };
use axum::{
    Router,
};
use log::debug;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AppState {
    firewall: Arc<Mutex<FirewallManager>>,
    rules: Arc<Mutex<RulesManager>>,
}

pub fn router(firewall: Arc<Mutex<FirewallManager>>, rules: Arc<Mutex<RulesManager>>) -> Router {
    let state = AppState { firewall, rules };

    debug!("Merging all routers into one");

    Router::new()
        .merge(iptables_router(firewall.get_iptables_manager(), rules.get_iptables_rules()))
        .with_state(state)
    
}

pub async fn run<T: IPTablesInterface + Send + Sync + 'static>(router: Router) {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();
    debug!("API server listening on 0.0.0.0:3000");
}
