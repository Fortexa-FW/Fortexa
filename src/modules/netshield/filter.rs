//! Filtering logic for netshield (eBPF/XDP)

use crate::modules::netshield::NetshieldModule;
use bincode::Encode;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

/// Custom deserializer to convert boolean to u8 (true -> 1, false -> 0)
fn deserialize_bool_as_u8<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Bool(b) => Ok(if b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u <= 1 {
                    Ok(u as u8)
                } else {
                    Err(D::Error::custom("enabled must be 0 or 1"))
                }
            } else {
                Err(D::Error::custom("invalid number for enabled field"))
            }
        }
        _ => Err(D::Error::custom("enabled must be a boolean or 0/1")),
    }
}

/// Direction of network traffic for filtering.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Encode)]
pub enum Direction {
    Incoming,
    Outgoing,
    Both,
}

/// Action to take on matching traffic.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Encode)]
pub enum Action {
    Block,
    Allow,
    Log,
}

/// Represents a network filtering rule (full structure).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Encode)]
pub struct NetshieldRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub group: Option<String>,
    pub direction: Direction,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub action: Action,
    #[serde(deserialize_with = "deserialize_bool_as_u8")]
    pub enabled: u8, // 0 = disabled, 1 = enabled
    pub priority: i32,
    pub parameters: HashMap<String, String>,
}

impl Default for NetshieldRule {
    fn default() -> Self {
        NetshieldRule {
            id: String::new(),
            name: String::new(),
            description: None,
            group: None,
            direction: Direction::Incoming,
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            action: Action::Block,
            enabled: 1,
            priority: 0,
            parameters: HashMap::new(),
        }
    }
}

const RULES_FILE: &str = "/var/lib/fortexa/netshield_rules.json";

/// Load all current network filtering rules from the rules file.
pub fn get_rules() -> Vec<NetshieldRule> {
    debug!("[Netshield] get_rules() called");
    if let Ok(data) = fs::read_to_string(RULES_FILE) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        vec![]
    }
}

/// Save all rules to the rules file.
fn save_rules(rules: &[NetshieldRule]) -> Result<(), String> {
    debug!("[Netshield] save_rules() called (count={})", rules.len());
    let json = serde_json::to_string_pretty(rules).map_err(|e| e.to_string())?;
    let path = Path::new(RULES_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut file = fs::File::create(path).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

/// Add a new network filtering rule.
pub fn add_rule(module: &mut NetshieldModule, mut rule: NetshieldRule) -> Result<(), String> {
    debug!(
        "[Netshield] add_rule() called: name={}, id={}",
        rule.name, rule.id
    );
    let mut rules = get_rules();
    if rule.id.is_empty() {
        rule.id = Uuid::new_v4().to_string();
    }
    if !rules.iter().any(|r| r.id == rule.id) {
        rules.push(rule);
        save_rules(&rules)?;
        // Apply to eBPF/XDP
        module.update_rules_map(&rules).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Delete a network filtering rule by id.
/// This removes the rule from both the persistent file and the eBPF/XDP map.
pub fn delete_rule(module: &mut NetshieldModule, rule_id: &str) -> Result<(), String> {
    debug!("[Netshield] delete_rule() called: id={rule_id}");
    let mut rules = get_rules();
    let len_before = rules.len();
    let index = rules.iter().position(|r| r.id == rule_id);
    rules.retain(|r| r.id != rule_id);
    if rules.len() != len_before {
        save_rules(&rules)?;
        // Always update the eBPF map with the new ruleset
        module.update_rules_map(&rules).map_err(|e| e.to_string())?;
        if let Some(idx) = index {
            let _ = module.remove_rule_from_map(idx as u32);
        }
        Ok(())
    } else {
        Err("Rule not found".to_string())
    }
}

/// Get a rule by id.
pub fn get_rule(id: &str) -> Option<NetshieldRule> {
    debug!("[Netshield] get_rule() called: id={id}");
    get_rules().into_iter().find(|r| r.id == id)
}

/// Update a rule by id. Replaces the rule with the same id.
pub fn update_rule(
    module: &mut NetshieldModule,
    id: &str,
    updated: NetshieldRule,
) -> Result<(), String> {
    debug!("[Netshield] update_rule() called: id={id}");
    let mut rules = get_rules();
    let mut found = false;
    for rule in &mut rules {
        if rule.id == id {
            *rule = updated;
            found = true;
            break;
        }
    }
    if found {
        save_rules(&rules)?;
        // Update eBPF/XDP map with the new rules
        module.update_rules_map(&rules).map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("Rule not found".to_string())
    }
}

/// Get all unique groups from rules.
pub fn get_groups() -> Vec<String> {
    debug!("[Netshield] get_groups() called");
    let mut groups: Vec<String> = get_rules().into_iter().filter_map(|r| r.group).collect();
    groups.sort();
    groups.dedup();
    groups
}

/// Get all rules in a specific group.
pub fn get_rules_by_group(group: &str) -> Vec<NetshieldRule> {
    debug!("[Netshield] get_rules_by_group() called: group={group}");
    get_rules()
        .into_iter()
        .filter(|r| r.group.as_deref() == Some(group))
        .collect()
}

/// Apply a single NetshieldRule to the system (placeholder for eBPF/XDP logic)
pub fn apply_rule_to_system(
    module: &mut NetshieldModule,
    rule: &NetshieldRule,
) -> Result<(), String> {
    info!(
        "[Netshield] Applying single rule to eBPF/XDP map: id={}, name={}",
        rule.id, rule.name
    );
    debug!("[Netshield] Rule details: {rule:?}");
    module
        .update_rules_map(&[rule.clone()])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Apply all rules to the system.
pub fn apply_all_rules(module: &mut NetshieldModule) -> Result<(), String> {
    let rules = get_rules();
    info!(
        "[Netshield] Applying all rules to eBPF/XDP map (count={})",
        rules.len()
    );
    for rule in &rules {
        debug!(
            "[Netshield] Rule: id={}, name={}, enabled={}",
            rule.id, rule.name, rule.enabled
        );
    }
    module.update_rules_map(&rules).map_err(|e| e.to_string())?;
    Ok(())
}
