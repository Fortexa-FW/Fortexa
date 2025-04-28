use super::iptables_daemon;
use crate::firewall::rules_core::RulesManager;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct FirewallDaemon {
    rules: Arc<tokio::sync::Mutex<RulesManager>>,
}

impl FirewallDaemon {
    pub async fn new(rules: Arc<tokio::sync::Mutex<RulesManager>>) -> Self {
        let rules_clone = Arc::clone(&rules);
        let rules_guard = rules.lock().await;
        iptables_daemon::run(Arc::new(tokio::sync::Mutex::new(
            rules_guard.get_iptables_rules().clone(),
        )));
        println!("Firewall daemon initialized with rules.");
        Self { rules: rules_clone }
    }

    pub fn rules(&self) -> &Mutex<RulesManager> {
        &self.rules
    }
}
