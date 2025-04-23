use crate::rules::{FirewallDirectionRules, FirewallRuleSet};
use ipnetwork::Ipv4Network;
use iptables::IPTables;
use log::{debug, info}; // info, error, debug, warn if needed

#[derive(Debug)]
pub enum FirewallError {
    IPTablesError(String),
    ChainError(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::IPTablesError(e) => write!(f, "IPTables error: {}", e),
            FirewallError::ChainError(e) => write!(f, "Chain error: {}", e),
        }
    }
}

pub struct FirewallManager {
    table: String,
    use_ipv6: bool,
}

impl FirewallManager {
    pub fn new(table: &str, use_ipv6: bool) -> Result<Self, FirewallError> {
        let ipt =
            iptables::new(use_ipv6).map_err(|e| FirewallError::IPTablesError(e.to_string()))?;

        // Cleanup old chains
        let _ = Self::delete_chains(&ipt, table);

        // Create chains
        ipt.new_chain(table, "FORTEXA_INPUT")
            .map_err(|e| FirewallError::ChainError(format!("Create INPUT chain: {}", e)))?;
        ipt.new_chain(table, "FORTEXA_OUTPUT")
            .map_err(|e| FirewallError::ChainError(format!("Create OUTPUT chain: {}", e)))?;

        // Insert chains into main chains
        ipt.insert(table, "INPUT", "-j FORTEXA_INPUT", 1)
            .map_err(|e| FirewallError::ChainError(format!("Insert INPUT jump: {}", e)))?;
        ipt.insert(table, "OUTPUT", "-j FORTEXA_OUTPUT", 1)
            .map_err(|e| FirewallError::ChainError(format!("Insert OUTPUT jump: {}", e)))?;

        Ok(Self {
            table: table.to_string(),
            use_ipv6,
        })
    }

    pub fn sync_rules(&self, rules: &FirewallRuleSet) -> Result<(), FirewallError> {
        let ipt = iptables::new(self.use_ipv6)
            .map_err(|e| FirewallError::IPTablesError(e.to_string()))?;

        debug!("Syncing rules to table {}", self.table);
        debug!("Input IPs: {:?}", rules.input.blocked_ips);
        debug!("Input Ports: {:?}", rules.input.blocked_ports);

        // Clear existing rules
        ipt.flush_chain(&self.table, "FORTEXA_INPUT")
            .map_err(|e| FirewallError::ChainError(format!("Flush INPUT: {}", e)))?;
        ipt.flush_chain(&self.table, "FORTEXA_OUTPUT")
            .map_err(|e| FirewallError::ChainError(format!("Flush OUTPUT: {}", e)))?;

        // INPUT rules
        Self::apply_rules(
            &ipt,
            &self.table,
            "FORTEXA_INPUT",
            &rules.input,
            |net, action| format!("-s {} -j {}", net, action),
            |port, action| {
                vec![
                    format!("-p tcp --dport {} -j {}", port, action),
                    format!("-p udp --dport {} -j {}", port, action),
                ]
            },
        )?;

        // OUTPUT rules
        Self::apply_rules(
            &ipt,
            &self.table,
            "FORTEXA_OUTPUT",
            &rules.output,
            |net, action| format!("-d {} -j {}", net, action),
            |port, action| {
                vec![
                    format!("-p tcp --dport {} -j {}", port, action),
                    format!("-p udp --dport {} -j {}", port, action),
                ]
            },
        )?;

        // Log final state
        let input_rules = ipt
            .list(&self.table, "FORTEXA_INPUT")
            .map_err(|e| FirewallError::ChainError(format!("List failed: {}", e)))?;
        debug!(
            "Current {} FORTEXA_INPUT rules:\n{:?}",
            self.table, input_rules
        );

        Ok(())
    }

    fn apply_rules<F, G>(
        ipt: &IPTables,
        table: &str,
        chain: &str,
        rules: &FirewallDirectionRules,
        ip_rule: F,
        port_rule: G,
    ) -> Result<(), FirewallError>
    where
        F: Fn(&Ipv4Network, &str) -> String,
        G: Fn(&u16, &str) -> Vec<String>,
    {
        // Whitelisted IPs (ACCEPT)
        for ip in &rules.whitelisted_ips {
            let rule = ip_rule(ip, "ACCEPT");
            ipt.append(table, chain, &rule)
                .map_err(|e| FirewallError::ChainError(format!("Append {}: {}", rule, e)))?;
            debug!("Whitelisted IP: {}", rule);
        }

        // Whitelisted ports (ACCEPT)
        for port in &rules.whitelisted_ports {
            for rule in port_rule(port, "ACCEPT") {
                ipt.append(table, chain, &rule)
                    .map_err(|e| FirewallError::ChainError(format!("Append {}: {}", rule, e)))?;
                debug!("Whitelisted port: {}", rule);
            }
        }

        // Blocked IPs (DROP)
        for ip in &rules.blocked_ips {
            if !rules.whitelisted_ips.contains(ip) {
                let rule = ip_rule(ip, "DROP");
                ipt.append(table, chain, &rule)
                    .map_err(|e| FirewallError::ChainError(format!("Append {}: {}", rule, e)))?;
                debug!("Blocked IP: {}", rule);
            }
        }

        // Blocked ports (DROP)
        for port in &rules.blocked_ports {
            if !rules.whitelisted_ports.contains(port) {
                for rule in port_rule(port, "DROP") {
                    ipt.append(table, chain, &rule).map_err(|e| {
                        FirewallError::ChainError(format!("Append {}: {}", rule, e))
                    })?;
                    debug!("Blocked port: {}", rule);
                }
            }
        }

        Ok(())
    }

    pub fn delete_rules(&self) -> Result<(), FirewallError> {
        let ipt = iptables::new(self.use_ipv6)
            .map_err(|e| FirewallError::IPTablesError(e.to_string()))?;

        ipt.delete(&self.table, "INPUT", "-j FORTEXA_INPUT").ok();
        ipt.delete(&self.table, "OUTPUT", "-j FORTEXA_OUTPUT").ok();
        ipt.flush_chain(&self.table, "FORTEXA_INPUT").ok();
        ipt.flush_chain(&self.table, "FORTEXA_OUTPUT").ok();
        ipt.delete_chain(&self.table, "FORTEXA_INPUT").ok();
        ipt.delete_chain(&self.table, "FORTEXA_OUTPUT").ok();

        info!("Cleaned up {} table rules", self.table);
        Ok(())
    }

    fn delete_chains(ipt: &IPTables, table: &str) -> Result<(), FirewallError> {
        ipt.delete(table, "INPUT", "-j FORTEXA_INPUT").ok();
        ipt.delete(table, "OUTPUT", "-j FORTEXA_OUTPUT").ok();
        ipt.flush_chain(table, "FORTEXA_INPUT").ok();
        ipt.flush_chain(table, "FORTEXA_OUTPUT").ok();
        ipt.delete_chain(table, "FORTEXA_INPUT").ok();
        ipt.delete_chain(table, "FORTEXA_OUTPUT").ok();
        Ok(())
    }
}
