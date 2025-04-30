use crate::{
    firewall::error::FirewallError,
    firewall::iptables::iptables_impl::{IPTablesInterface, IPTablesWrapper},
    firewall::iptables::rules::{IPTablesDirectionRules, IPTablesRuleSet},
};
use ipnetwork::Ipv4Network;
use log::debug; // info, error, debug, warn if needed

#[derive(Clone)]
pub struct IPTablesManager<T: IPTablesInterface = IPTablesWrapper> {
    table: String,
    use_ipv6: bool,
    ipt: T,
    input_chain: String,
    output_chain: String,
}

impl<T: IPTablesInterface> IPTablesManager<T> {
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

    pub fn sync_rules(&self, rules: &IPTablesRuleSet) -> Result<(), FirewallError> {
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
        rules: &IPTablesDirectionRules,
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
