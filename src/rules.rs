use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallRuleSet {
    #[serde(default = "default_table")]
    pub table: String,
    pub input: FirewallDirectionRules,
    pub output: FirewallDirectionRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallDirectionRules {
    pub blocked_ips: HashSet<Ipv4Network>,
    pub blocked_ports: HashSet<u16>,
    pub whitelisted_ips: HashSet<Ipv4Network>,
    pub whitelisted_ports: HashSet<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

fn default_table() -> String {
    "filter".to_string()
}

impl FirewallRuleSet {
    pub fn load_from_file(path: &str) -> FirewallRuleSet {
        let data = std::fs::read_to_string(path).unwrap_or_default();
        let rules: FirewallRuleSet = serde_json::from_str(&data).unwrap_or_else(|e| {
            log::error!("Failed to parse rules.json: {}", e);
            FirewallRuleSet::default()
        });
        log::debug!("Loaded rules: {:?}", rules);
        rules
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, data);
        }
    }
}
