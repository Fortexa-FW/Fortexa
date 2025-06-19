use anyhow::{Context, Result};
use iptables::IPTables;
use log::{debug, info};
use std::process::Command;

use crate::core::rules::{Action, Direction, Rule};

/// IPTables filter
pub struct IptablesFilter {
    /// The chain prefix
    chain_prefix: String,

    /// The IPTables instance
    iptables: IPTables,
}

static TABLE_NAME: &str = "filter";

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

    /// Apply a rule
    fn apply_rule(&self, rule: &Rule) -> Result<()> {
        // Determine the chain
        let chain = match rule.direction {
            Direction::Input => format!("{}_INPUT", self.chain_prefix),
            Direction::Output => format!("{}_OUTPUT", self.chain_prefix),
            Direction::Forward => format!("{}_FORWARD", self.chain_prefix),
        };

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
}
