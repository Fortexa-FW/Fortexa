use serde::{Serialize, Deserialize};
use std::net::Ipv4Addr;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallRuleSet {
    pub input: FirewallDirectionRules,
    pub output: FirewallDirectionRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallDirectionRules {
    pub blocked_ips: HashSet<Ipv4Addr>,
    pub blocked_ports: HashSet<u16>,
}


impl FirewallRuleSet {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_default()
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, data);
        }
    }
}
