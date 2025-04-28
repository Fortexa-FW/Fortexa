use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IPTablesRuleSet {
    #[serde(default = "default_table")]
    pub table: String,
    pub input: IPTablesDirectionRules,
    pub output: IPTablesDirectionRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IPTablesDirectionRules {
    pub blocked_ips: HashSet<Ipv4Network>,
    pub blocked_ports: HashSet<u16>,
    pub whitelisted_ips: HashSet<Ipv4Network>,
    pub whitelisted_ports: HashSet<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

fn default_table() -> String {
    "filter".to_string()
}

impl IPTablesRuleSet {
    pub fn load_from_file(path: &str) -> IPTablesRuleSet {
        let data = fs::read_to_string(path).unwrap_or_default();
        let rules: IPTablesRuleSet = serde_json::from_str(&data).unwrap_or_else(|e| {
            log::error!("Failed to parse rules.json: {}", e);
            IPTablesRuleSet::default()
        });
        log::debug!("Loaded rules: {:?}", rules);
        rules
    }

    pub fn save_to_file(&self, path: &str) {
        if let Err(e) = serde_json::to_string_pretty(self)
            .map_err(|e| e.to_string())
            .and_then(|json| fs::write(path, json).map_err(|e| e.to_string()))
        {
            log::error!("Failed to save rules to file {}: {}", path, e);
        }
    }
}
