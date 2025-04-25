use crate::{
    firewall::error::FirewallError,
    firewall::iptables::{IPTablesInterface, IPTablesWrapper},
    rules::{FirewallDirectionRules, FirewallRuleSet},
};
use ipnetwork::Ipv4Network;
use log::debug; // info, error, debug, warn if needed

pub struct FirewallManager<T: IPTablesInterface = IPTablesWrapper> {
    table: String,
    use_ipv6: bool,
    ipt: T,
    input_chain: String,
    output_chain: String,
}

impl<T: IPTablesInterface> FirewallManager<T> {
    pub fn new(table: &str, use_ipv6: bool, ipt: T) -> Result<Self, FirewallError> {
        let base_chain = "FORTEXA"; // Default base name
        let input_chain = format!("{}_INPUT", base_chain);
        let output_chain = format!("{}_OUTPUT", base_chain);

        // Cleanup old chains
        let _ = Self::delete_chains(&ipt, table, &input_chain, &output_chain);

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
            ipt,
            input_chain,
            output_chain,
        })
    }

    pub fn chain(mut self, base_name: &str) -> Result<Self, FirewallError> {
        let new_input = format!("{}_INPUT", base_name);
        let new_output = format!("{}_OUTPUT", base_name);

        self.ipt
            .new_chain(&self.table, &new_input)
            .map_err(|e| FirewallError::ChainError(format!("Create INPUT chain: {}", e)))?;
        self.ipt
            .new_chain(&self.table, &new_output)
            .map_err(|e| FirewallError::ChainError(format!("Create OUTPUT chain: {}", e)))?;

        self.ipt
            .delete(&self.table, "INPUT", &format!("-j {}", self.input_chain))?;
        self.ipt
            .delete(&self.table, "OUTPUT", &format!("-j {}", self.output_chain))?;

        self.ipt
            .insert(&self.table, "INPUT", &format!("-j {}", new_input), 1)?;
        self.ipt
            .insert(&self.table, "OUTPUT", &format!("-j {}", new_output), 1)?;

        Self::delete_chains(
            &self.ipt,
            &self.table,
            &self.input_chain,
            &self.output_chain,
        )?;

        self.input_chain = new_input;
        self.output_chain = new_output;

        Ok(self)
    }

    pub fn sync_rules(&self, rules: &FirewallRuleSet) -> Result<(), FirewallError> {
        debug!(
            "Syncing rules to table {} (IPv6: {})",
            self.table, self.use_ipv6
        );
        debug!("Input IPs: {:?}", rules.input.blocked_ips);
        debug!("Input Ports: {:?}", rules.input.blocked_ports);

        // Clear existing rules
        self.ipt
            .flush_chain(&self.table, &self.input_chain)
            .map_err(|e| FirewallError::ChainError(format!("Flush INPUT: {}", e)))?;
        self.ipt
            .flush_chain(&self.table, &self.output_chain)
            .map_err(|e| FirewallError::ChainError(format!("Flush OUTPUT: {}", e)))?;

        let mut batch = Vec::new();
        batch.push(format!("*{}", self.table));
        batch.push(format!(":{} - [0:0]", self.input_chain));
        batch.push(format!(":{} - [0:0]", self.output_chain));

        // Apply INPUT rules
        Self::add_rules_to_batch(
            &mut batch,
            &self.input_chain,
            &rules.input,
            |net, action| format!("-s {} -j {}", net, action),
            |port, action| {
                vec![
                    format!("-p tcp --dport {} -j {}", port, action),
                    format!("-p udp --dport {} -j {}", port, action),
                ]
            },
        );

        // Apply OUTPUT rules
        Self::add_rules_to_batch(
            &mut batch,
            &self.output_chain,
            &rules.output,
            |net, action| format!("-d {} -j {}", net, action),
            |port, action| {
                vec![
                    format!("-p tcp --dport {} -j {}", port, action),
                    format!("-p udp --dport {} -j {}", port, action),
                ]
            },
        );

        // Finalize batch
        batch.push("COMMIT".to_string());
        batch.push("".to_string());

        // Execute atomic batch
        debug!("Atomic batch:\n{}", batch.join("\n"));
        self.ipt
            .batch_execute(&batch)
            .map_err(|e| FirewallError::ChainError(format!("Batch failed: {}", e)))?;

        // Log final state
        let input_rules = self
            .ipt
            .list(&self.table, &self.input_chain)
            .map_err(|e| FirewallError::ChainError(format!("List failed: {}", e)))?;
        debug!(
            "Current {} {} rules:\n{:?}",
            self.table, self.input_chain, input_rules
        );

        Ok(())
    }

    fn add_rules_to_batch<F, G>(
        batch: &mut Vec<String>,
        chain: &str,
        rules: &FirewallDirectionRules,
        ip_rule: F,
        port_rule: G,
    ) where
        F: Fn(&Ipv4Network, &str) -> String,
        G: Fn(&u16, &str) -> Vec<String>,
    {
        // Format rules with chain context
        let format_rule = |rule: String| format!("-A {} {}", chain, rule);

        // Whitelisted IPs
        for ip in &rules.whitelisted_ips {
            batch.push(format_rule(ip_rule(ip, "ACCEPT")));
        }

        // Whitelisted ports
        for port in &rules.whitelisted_ports {
            for rule in port_rule(port, "ACCEPT") {
                batch.push(format_rule(rule));
            }
        }

        // Blocked IPs
        for ip in &rules.blocked_ips {
            if !rules.whitelisted_ips.contains(ip) {
                batch.push(format_rule(ip_rule(ip, "DROP")));
            }
        }

        // Blocked ports
        for port in &rules.blocked_ports {
            if !rules.whitelisted_ports.contains(port) {
                for rule in port_rule(port, "DROP") {
                    batch.push(format_rule(rule));
                }
            }
        }
    }

    pub fn delete_rules(&self) -> Result<(), FirewallError> {
        Self::delete_chains(
            &self.ipt,
            &self.table,
            &self.input_chain,
            &self.output_chain,
        )
    }

    fn delete_chains(
        ipt: &dyn IPTablesInterface,
        table: &str,
        input_chain: &str,
        output_chain: &str,
    ) -> Result<(), FirewallError> {
        ipt.delete(table, "INPUT", &format!("-j {}", input_chain))
            .ok();
        ipt.delete(table, "OUTPUT", &format!("-j {}", output_chain))
            .ok();
        ipt.flush_chain(table, input_chain).ok();
        ipt.flush_chain(table, output_chain).ok();
        ipt.delete_chain(table, input_chain).ok();
        ipt.delete_chain(table, output_chain).ok();
        Ok(())
    }

    pub fn allow_established(&self) -> Result<(), FirewallError> {
        self.ipt
            .append(
                &self.table,
                &self.input_chain,
                "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            )
            .map_err(FirewallError::ChainError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    struct TestEnvironment {
        table: String,
        chain: String,
        ipt: IPTablesWrapper,
    }

    impl TestEnvironment {
        fn new(table: &str, chain: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let ipt = IPTablesWrapper::new(false)?;
            let _ = ipt.delete_chain(table, chain);
            let _ = ipt.flush_chain(table, chain);
            ipt.new_chain(table, chain)?;
            Ok(Self {
                table: table.to_string(),
                chain: chain.to_string(),
                ipt,
            })
        }

        fn create_manager(&self) -> Result<FirewallManager<IPTablesWrapper>, FirewallError> {
            FirewallManager::new(&self.table, false, self.ipt.clone())
                .and_then(|m| m.chain(&self.chain))
        }
    }

    impl Drop for TestEnvironment {
        fn drop(&mut self) {
            let _ = self.ipt.flush_chain(&self.table, &self.chain);
            let _ = self.ipt.delete_chain(&self.table, &self.chain);
        }
    }

    #[test]
    #[ignore = "requires iptables access and root privileges"]
    fn test_firewall_manager_initialization() -> Result<(), Box<dyn std::error::Error>> {
        let table = "filter";
        let chain = "fortexa_init_test";
        let env = TestEnvironment::new(table, chain)?;

        let manager = env.create_manager()?;

        // Verify chains exist
        let chains = env.ipt.list(table, "")?;
        assert!(chains.iter().any(|c| c.contains(&format!(":{}", chain))));

        Ok(())
    }

    #[test]
    #[ignore = "requires iptables access and root privileges"]
    fn test_rule_sync_order() -> Result<(), Box<dyn std::error::Error>> {
        let table = "filter";
        let chain = "fortexa_order_test";
        let env = TestEnvironment::new(table, chain)?;
        let manager = env.create_manager()?;

        let mut rules = FirewallRuleSet::default();
        rules.input.whitelisted_ips.insert("10.0.0.5/32".parse()?);
        rules.input.blocked_ips.insert("192.168.1.100/32".parse()?);

        manager.sync_rules(&rules)?;

        // Verify rule order
        let current_rules = env.ipt.list(table, chain)?;
        let accept_pos = current_rules.iter().position(|r| r.contains("ACCEPT"));
        let drop_pos = current_rules.iter().position(|r| r.contains("DROP"));

        assert!(
            accept_pos < drop_pos,
            "Whitelist rules should come before block rules\nRules: {:?}",
            current_rules
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires iptables access and root privileges"]
    fn test_rule_deletion() -> Result<(), Box<dyn std::error::Error>> {
        let table = "filter";
        let chain = "fortexa_cleanup_test";
        let env = TestEnvironment::new(table, chain)?;
        let manager = env.create_manager()?;

        // Add some rules
        let mut rules = FirewallRuleSet::default();
        rules.input.blocked_ips.insert("192.168.1.100/32".parse()?);
        manager.sync_rules(&rules)?;

        // Delete rules
        manager.delete_rules()?;

        // Verify chain is empty
        let current_rules = env.ipt.list(table, chain)?;
        assert!(
            current_rules.is_empty(),
            "Rules should be empty after deletion: {:?}",
            current_rules
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires iptables access and root privileges"]
    fn test_allow_established() -> Result<(), Box<dyn std::error::Error>> {
        let table = "filter";
        let chain = "fortexa_established_test";
        let env = TestEnvironment::new(table, chain)?;
        let manager = env.create_manager()?;

        manager.allow_established()?;

        let rules = env.ipt.list(table, chain)?;
        assert!(
            rules.iter().any(|r| r.contains("ESTABLISHED,RELATED")),
            "Should find ESTABLISHED rule"
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires iptables access and root privileges"]
    fn test_port_rules() -> Result<(), Box<dyn std::error::Error>> {
        let table = "filter";
        let chain = "fortexa_port_test";
        let env = TestEnvironment::new(table, chain)?;
        let manager = env.create_manager()?;

        let mut rules = FirewallRuleSet::default();
        rules.input.whitelisted_ports.insert(443);
        rules.input.blocked_ports.insert(22);

        manager.sync_rules(&rules)?;

        let current_rules = env.ipt.list(table, chain)?;
        assert!(
            current_rules
                .iter()
                .any(|r| r.contains("dport 443") && r.contains("ACCEPT")),
            "Missing port 443 ACCEPT rule"
        );
        assert!(
            current_rules
                .iter()
                .any(|r| r.contains("dport 22") && r.contains("DROP")),
            "Missing port 22 DROP rule"
        );

        Ok(())
    }
}
