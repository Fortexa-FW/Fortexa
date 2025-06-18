use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::storage::filedb::FileDB;

/// Rule direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Incoming traffic
    Input,

    /// Outgoing traffic
    Output,

    /// Forwarded traffic
    Forward,
}

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Accept the packet
    Accept,

    /// Drop the packet
    Drop,

    /// Reject the packet
    Reject,

    /// Log the packet
    Log,
}

/// A firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub enabled: bool,

    /// Rule priority (lower numbers have higher priority)
    pub priority: i32,

    /// Module-specific parameters
    pub parameters: HashMap<String, String>,
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
            enabled: true,
            priority,
            parameters: HashMap::new(),
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
        Ok(rules.into_iter().filter(|r| r.enabled).collect())
    }
}
