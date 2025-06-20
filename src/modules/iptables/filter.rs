use anyhow::{Context, Result};
use iptables::IPTables;
use log::{debug, info};
use std::process::Command;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

use crate::core::rules::{Action, Direction, Rule};

/// IPTables filter
pub struct IptablesFilter {
    /// The chain prefix
    chain_prefix: String,

    /// The IPTables instance
    iptables: IPTables,
}

static TABLE_NAME: &str = "filter";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CustomChainEntry {
    pub name: String,
    pub reference_from: Option<String>,
}

impl IptablesFilter {
    /// Create a new IPTables filter
    pub fn new(chain_prefix: &str) -> Result<Self> {
        // TODO: make a config for ipv6 support (for now we assume only ipv4)
        let iptables = iptables::new(false)
            .map_err(|e| anyhow::anyhow!("{}", e))
            .context("Failed to create IPTables instance")?;

        Ok(Self {
            chain_prefix: chain_prefix.to_string(),
            iptables,
        })
    }

    /// Initialize the filter
    pub fn init(&self) -> Result<()> {
        // Create the chains if they don't exist
        self.create_chain(&format!("{}_INPUT", self.chain_prefix))?;
        self.create_chain(&format!("{}_OUTPUT", self.chain_prefix))?;
        self.create_chain(&format!("{}_FORWARD", self.chain_prefix))?;

        // Add jump rules to the built-in chains
        self.add_jump_rules()?;

        Ok(())
    }

    /// Create a chain
    fn create_chain(&self, chain: &str) -> Result<()> {
        // Check if the chain exists
        let output = Command::new("iptables")
            .args(["-t", TABLE_NAME, "-L", chain])
            .output()
            .context("Failed to execute iptables command")?;

        debug!("Checking if chain {} exists or not", chain);
        if !output.status.success() {
            // Chain doesn't exist, create it
            info!("Creating chain: {}", chain);
            self.iptables
                .new_chain(TABLE_NAME, chain)
                .map_err(|e| anyhow::anyhow!("{}", e))
                .context(format!("Failed to create chain: {}", chain))?;
        } else {
            debug!("Chain already exists: {}", chain);
        }

        Ok(())
    }

    /// Add jump rules to the built-in chains
    fn add_jump_rules(&self) -> Result<()> {
        // Check if the jump rules exist
        let input_exists =
            self.jump_rule_exists("INPUT", &format!("{}_INPUT", self.chain_prefix))?;
        let output_exists =
            self.jump_rule_exists("OUTPUT", &format!("{}_OUTPUT", self.chain_prefix))?;
        let forward_exists =
            self.jump_rule_exists("FORWARD", &format!("{}_FORWARD", self.chain_prefix))?;

        // Add the jump rules if they don't exist
        if !input_exists {
            info!("Adding jump rule from INPUT to {}_INPUT", self.chain_prefix);
            self.iptables
                .append(
                    TABLE_NAME,
                    "INPUT",
                    &format!("-j {}_INPUT", self.chain_prefix),
                )
                .map_err(|e| anyhow::anyhow!("{}", e))
                .context("Failed to add jump rule to INPUT chain")?;
        }

        if !output_exists {
            info!(
                "Adding jump rule from OUTPUT to {}_OUTPUT",
                self.chain_prefix
            );
            self.iptables
                .append(
                    TABLE_NAME,
                    "OUTPUT",
                    &format!("-j {}_OUTPUT", self.chain_prefix),
                )
                .map_err(|e| anyhow::anyhow!("{}", e))
                .context("Failed to add jump rule to OUTPUT chain")?;
        }

        if !forward_exists {
            info!(
                "Adding jump rule from FORWARD to {}_FORWARD",
                self.chain_prefix
            );
            self.iptables
                .append(
                    TABLE_NAME,
                    "FORWARD",
                    &format!("-j {}_FORWARD", self.chain_prefix),
                )
                .map_err(|e| anyhow::anyhow!("{}", e))
                .context("Failed to add jump rule to FORWARD chain")?;
        }

        Ok(())
    }

    /// Check if a jump rule exists
    fn jump_rule_exists(&self, source_chain: &str, target_chain: &str) -> Result<bool> {
        let output = Command::new("iptables")
            .args(["-C", source_chain, "-j", target_chain])
            .output()
            .context("Failed to execute iptables command")?;

        Ok(output.status.success())
    }

    /// Apply rules to the filter
    pub fn apply_rules(&self, rules: &[Rule]) -> Result<()> {
        // Clear existing rules
        self.clear_rules()?;

        // Apply the rules
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            self.apply_rule(rule)?;
        }
        Ok(())
    }

    /// Clear existing rules
    fn clear_rules(&self) -> Result<()> {
        info!("Clearing existing rules");

        // Flush the chains
        self.iptables
            .flush_chain(TABLE_NAME, &format!("{}_INPUT", self.chain_prefix))
            .map_err(|e| anyhow::anyhow!("{}", e))
            .context("Failed to flush INPUT chain")?;
        self.iptables
            .flush_chain(TABLE_NAME, &format!("{}_OUTPUT", self.chain_prefix))
            .map_err(|e| anyhow::anyhow!("{}", e))
            .context("Failed to flush OUTPUT chain")?;
        self.iptables
            .flush_chain(TABLE_NAME, &format!("{}_FORWARD", self.chain_prefix))
            .map_err(|e| anyhow::anyhow!("{}", e))
            .context("Failed to flush FORWARD chain")?;

        Ok(())
    }

    /// Apply rules to the filter with auto_create_chain
    pub fn apply_rules_with_auto_create(&self, rules: &[Rule], auto_create_chain: bool) -> Result<()> {
        self.clear_rules()?;
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            self.apply_rule_with_flag(rule, auto_create_chain)?;
        }
        Ok(())
    }

    /// Apply a rule with auto_create_chain
    fn apply_rule_with_flag(&self, rule: &Rule, auto_create_chain: bool) -> Result<()> {
        let chain = match rule.direction {
            Direction::Input => format!("{}_INPUT", self.chain_prefix),
            Direction::Output => format!("{}_OUTPUT", self.chain_prefix),
            Direction::Forward => format!("{}_FORWARD", self.chain_prefix),
        };
        if auto_create_chain {
            self.ensure_chain_exists(&chain)?;
        }
        // Build the rule arguments
        let mut args = Vec::new();

        // Add source IP
        if let Some(ref source) = rule.source {
            args.push("-s".to_string());
            args.push(source.clone());
        }

        // Add destination IP
        if let Some(ref destination) = rule.destination {
            args.push("-d".to_string());
            args.push(destination.clone());
        }

        // Add protocol
        if let Some(ref protocol) = rule.protocol {
            args.push("-p".to_string());
            args.push(protocol.clone());

            // Add ports if protocol is tcp or udp
            if protocol == "tcp" || protocol == "udp" {
                // Add source port
                if let Some(ref source_port) = rule.source_port {
                    args.push("--sport".to_string());
                    args.push(source_port.clone());
                }

                // Add destination port
                if let Some(ref destination_port) = rule.destination_port {
                    args.push("--dport".to_string());
                    args.push(destination_port.clone());
                }
            }
        }

        // Add action
        match rule.action {
            Action::Accept => args.push("-j ACCEPT".to_string()),
            Action::Drop => args.push("-j DROP".to_string()),
            Action::Reject => args.push("-j REJECT".to_string()),
            Action::Log => {
                args.push("-j LOG".to_string());
                args.push("--log-prefix".to_string());
                args.push(format!("\"[FORTEXA] {}: \"", rule.name));
            }
        }

        // Execute the command
        let rule_str = args.join(" ");
        debug!("Adding rule to {}: {}", chain, rule_str);
        self.iptables
            .append(TABLE_NAME, &chain, &rule_str)
            .map_err(|e| anyhow::anyhow!("{}", e))
            .context(format!("Failed to add rule to chain: {}", chain))?;
        Ok(())
    }

    /// The default apply_rule now always uses auto_create_chain = false
    fn apply_rule(&self, rule: &Rule) -> Result<()> {
        self.apply_rule_with_flag(rule, false)
    }

    fn ensure_chain_exists(&self, chain: &str) -> Result<()> {
        let output = Command::new("iptables")
            .args(["-t", TABLE_NAME, "-L", chain])
            .output()
            .context("Failed to execute iptables command")?;
        if !output.status.success() {
            self.iptables
                .new_chain(TABLE_NAME, chain)
                .map_err(|e| anyhow::anyhow!("{}", e))
                .context(format!("Failed to create chain: {}", chain))?;
        }
        Ok(())
    }

    pub fn cleanup(&self) -> Result<()> {
        let chains = [
            format!("{}_INPUT", self.chain_prefix),
            format!("{}_OUTPUT", self.chain_prefix),
            format!("{}_FORWARD", self.chain_prefix),
        ];
        let builtins = ["INPUT", "OUTPUT", "FORWARD"];

        // Remove jump rules from built-in chains
        for (builtin, custom) in builtins.iter().zip(chains.iter()) {
            let _ = self
                .iptables
                .delete(TABLE_NAME, builtin, &format!("-j {}", custom));
        }

        // Flush and delete custom chains
        for chain in chains.iter() {
            let _ = self.iptables.flush_chain(TABLE_NAME, chain);
            let _ = self.iptables.delete_chain(TABLE_NAME, chain);
        }
        Ok(())
    }

    pub fn create_custom_chain(&self, name: &str, reference_from: Option<&str>) -> anyhow::Result<()> {
        match self.iptables.new_chain("filter", name) {
            Ok(_) => {},
            Err(e) => {
                let msg = format!("{}", e);
                if !msg.contains("Chain already exists") {
                    return Err(anyhow::anyhow!("{}", msg));
                }
                // else: chain already exists, treat as success
            }
        }
        if let Some(builtin) = reference_from {
            if !self.jump_rule_exists(builtin, name)? {
                self.iptables
                    .append("filter", builtin, &format!("-j {}", name))
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
            }
        }
        Ok(())
    }

    pub fn delete_custom_chain(&self, name: &str, reference_from: Option<&str>) -> anyhow::Result<()> {
        if let Some(builtin) = reference_from {
            let _ = self.iptables.delete("filter", builtin, &format!("-j {}", name));
        }
        // Flush and delete the chain
        let _ = self.iptables.flush_chain("filter", name);
        let _ = self.iptables.delete_chain("filter", name);
        Ok(())
    }

    pub fn apply_custom_chains_from_file(path: &str) -> Result<()> {
        if !Path::new(path).exists() {
            return Ok(()); // Nothing to do
        }
        let data = fs::read_to_string(path)
            .context(format!("Failed to read custom chains file: {}", path))?;
        let chains: Vec<CustomChainEntry> = serde_json::from_str(&data)
            .context("Failed to parse custom chains file")?;
        let filter = IptablesFilter::new("")?; // Use empty prefix for direct names
        for entry in chains {
            filter.create_custom_chain(&entry.name, entry.reference_from.as_deref())?;
        }
        Ok(())
    }

    pub fn add_chain_to_file(path: &str, entry: &CustomChainEntry) -> Result<()> {
        let mut chains = if Path::new(path).exists() {
            let data = fs::read_to_string(path)?;
            serde_json::from_str(&data).unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };
        if !chains.iter().any(|c: &CustomChainEntry| c.name == entry.name) {
            chains.push(entry.clone());
        }
        let json = serde_json::to_string_pretty(&chains)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn remove_chain_from_file(path: &str, name: &str) -> Result<()> {
        if !Path::new(path).exists() {
            return Ok(());
        }
        let data = fs::read_to_string(path)?;
        let mut chains: Vec<CustomChainEntry> = serde_json::from_str(&data).unwrap_or_else(|_| vec![]);
        chains.retain(|c| c.name != name);
        let json = serde_json::to_string_pretty(&chains)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn add_rule_with_auto_create(&self, rules_manager: &crate::core::rules::RulesManager, rule: crate::core::rules::Rule, auto_create_chain: bool) -> Result<String> {
        let rule_id = rules_manager.add_rule(rule.clone())?;
        let rules = rules_manager.get_enabled_rules()?;
        self.apply_rules_with_auto_create(&rules, auto_create_chain)?;
        Ok(rule_id)
    }

    pub fn update_rule_with_auto_create(&self, rules_manager: &crate::core::rules::RulesManager, rule: crate::core::rules::Rule, auto_create_chain: bool) -> Result<()> {
        rules_manager.update_rule(rule)?;
        let rules = rules_manager.get_enabled_rules()?;
        self.apply_rules_with_auto_create(&rules, auto_create_chain)?;
        Ok(())
    }
}
