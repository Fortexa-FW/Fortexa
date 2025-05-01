use crate::{
    IPTablesInterface, api::iptables::api_iptables::iptables_router,
    firewall::core::FirewallManager, firewall::rules_core::RulesManager,
};
use axum::Router;
use log::debug;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn router(
    firewall: Arc<Mutex<FirewallManager>>,
    rules: Arc<Mutex<RulesManager>>,
) -> Router {
    debug!("Merging all routers into one");

    Router::new().merge(iptables_router(
        Arc::new(Mutex::new(
            (*firewall.clone().lock().await.get_iptables_manager()).clone(),
        )),
        Arc::new(Mutex::new(
            rules.clone().lock().await.get_iptables_rules().clone(),
        )),
    ))
}

pub async fn run<T: IPTablesInterface + Send + Sync + 'static>(
    router: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await?;
    debug!("API server listening on 0.0.0.0:3000");
    Ok(())
}
