use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::storage::filedb::FileDB;

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

/// Rule direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Direction {
    Incoming = 0,
    Outgoing = 1,
    Both = 2,
}

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Action {
    Block = 0,
    Allow = 1,
    Log = 3,
}

/// A firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct Rule {
    /// Unique identifier for the rule
    pub id: String,

    /// Rule name
    pub name: String,

    /// Rule description
    pub description: Option<String>,

    /// Rule direction
    pub direction: Direction,

    /// Source IP address or network
    pub source: Option<String>,

    /// Destination IP address or network
    pub destination: Option<String>,

    /// Source port or port range
    pub source_port: Option<String>,

    /// Destination port or port range
    pub destination_port: Option<String>,

    /// Protocol (tcp, udp, icmp, etc.)
    pub protocol: Option<String>,

    /// Rule action
    pub action: Action,

    /// Whether the rule is enabled
    #[serde(deserialize_with = "deserialize_bool_as_u8")]
    pub enabled: u8, // 0 = disabled, 1 = enabled

    /// Rule priority (lower numbers have higher priority)
    pub priority: i32,

    /// Module-specific parameters
    pub parameters: HashMap<String, String>,

    /// Source IP address in network byte order, 0 for any
    #[serde(default, deserialize_with = "null_to_zero_u32", skip_serializing)]
    pub source_ip: u32,

    /// Destination IP address in network byte order, 0 for any
    #[serde(default, deserialize_with = "null_to_zero_u32", skip_serializing)]
    pub destination_ip: u32,

    /// Source port in network byte order, 0 for any
    #[serde(default, deserialize_with = "null_to_zero_u16", skip_serializing)]
    pub source_port_network: u16,

    /// Destination port in network byte order, 0 for any
    #[serde(default, deserialize_with = "null_to_zero_u16", skip_serializing)]
    pub destination_port_network: u16,

    /// IP protocol (TCP=6, UDP=17, etc.), 0 for any
    #[serde(default, deserialize_with = "null_to_zero_u8", skip_serializing)]
    pub protocol_number: u8,
}

impl Rule {
    /// Create a new rule
    pub fn new(name: String, direction: Direction, action: Action, priority: i32) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description: None,
            direction,
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            action,
            enabled: 1,
            priority,
            parameters: HashMap::new(),
            source_ip: 0,
            destination_ip: 0,
            source_port_network: 0,
            destination_port_network: 0,
            protocol_number: 0,
        }
    }

    // TODO: We can add a function here to parse CLI string into a Rule definition
}

/// Rules manager
pub struct RulesManager {
    /// The storage backend
    storage: Arc<RwLock<FileDB>>,
}

impl RulesManager {
    /// Create a new rules manager
    pub fn new(storage_path: &str) -> Result<Self> {
        let storage = Arc::new(RwLock::new(FileDB::new(storage_path)?));
        Ok(Self { storage })
    }

    /// Add a new rule
    pub fn add_rule(&self, rule: Rule) -> Result<String> {
        let mut storage = self.storage.write().unwrap();
        storage.add_rule(rule)
    }

    /// Get a rule by ID
    pub fn get_rule(&self, id: &str) -> Result<Rule> {
        let storage = self.storage.read().unwrap();
        storage.get_rule(id)
    }

    /// Update a rule
    pub fn update_rule(&self, rule: Rule) -> Result<()> {
        let mut storage = self.storage.write().unwrap();
        storage.update_rule(rule)
    }

    /// Delete a rule
    pub fn delete_rule(&self, id: &str) -> Result<()> {
        let mut storage = self.storage.write().unwrap();
        storage.delete_rule(id)
    }

    /// List all rules
    pub fn list_rules(&self) -> Result<Vec<Rule>> {
        let storage = self.storage.read().unwrap();
        storage.list_rules()
    }

    /// Delete all rules
    pub fn reset_rules(&self) -> Result<()> {
        let mut storage = self.storage.write().unwrap();
        storage.reset_rules()
    }

    /// Get all rules for a direction
    pub fn get_rules_for_direction(&self, direction: Direction) -> Result<Vec<Rule>> {
        let storage = self.storage.read().unwrap();
        let rules = storage.list_rules()?;
        Ok(rules
            .into_iter()
            .filter(|r| r.direction == direction)
            .collect())
    }

    /// Get all enabled rules
    pub fn get_enabled_rules(&self) -> Result<Vec<Rule>> {
        let storage = self.storage.read().unwrap();
        let rules = storage.list_rules()?;
        Ok(rules.into_iter().filter(|r| r.enabled == 1).collect())
    }
}

fn null_to_zero_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<u32>::deserialize(deserializer)?.unwrap_or(0))
}

fn null_to_zero_u16<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<u16>::deserialize(deserializer)?.unwrap_or(0))
}

fn null_to_zero_u8<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<u8>::deserialize(deserializer)?.unwrap_or(0))
}
