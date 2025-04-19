use iptables::IPTables;
use std::net::Ipv4Addr;
use crate::rules::{FirewallRuleSet, FirewallDirectionRules};
use log::{info, error, debug, warn};

pub struct FirewallManager;

impl FirewallManager {
    pub fn new() -> Self {
        let _ = Self::delete_rules();
        let ipt = iptables::new(false).unwrap();
        
        // Create chains
        ipt.new_chain("filter", "FORTEXA_INPUT").unwrap();
        ipt.new_chain("filter", "FORTEXA_OUTPUT").unwrap();

        // Insert chains at the start of INPUT/OUTPUT
        ipt.insert("filter", "INPUT", "-j FORTEXA_INPUT", 1).unwrap();
        ipt.insert("filter", "OUTPUT", "-j FORTEXA_OUTPUT", 1).unwrap();

        FirewallManager
    }

    pub fn sync_rules(rules: &FirewallRuleSet) -> Result<(), String> {
        let ipt = iptables::new(false).map_err(|e| e.to_string())?;
            
        debug!("Syncing rules:");
        debug!("Input IPs: {:?}", rules.input.blocked_ips);
        debug!("Input Ports: {:?}", rules.input.blocked_ports);
        debug!("Output IPs: {:?}", rules.output.blocked_ips);
        debug!("Output Ports: {:?}", rules.output.blocked_ports);

        // Clear existing rules
        ipt.flush_chain("filter", "FORTEXA_INPUT").map_err(|e| e.to_string())?;
        ipt.flush_chain("filter", "FORTEXA_OUTPUT").map_err(|e| e.to_string())?;

        // INPUT rules (incoming traffic)
        Self::apply_rules(
            &ipt,
            "FORTEXA_INPUT",
            &rules.input,
            |ip| format!("-s {}/32 -j DROP", ip),
            |port| vec![
                format!("-p tcp --dport {} -j DROP", port),
                format!("-p udp --dport {} -j DROP", port),
            ],
        )?;

        // OUTPUT rules (outgoing traffic)
        Self::apply_rules(
            &ipt,
            "FORTEXA_OUTPUT",
            &rules.output,
            |ip| format!("-d {}/32 -j DROP", ip),
            |port| vec![
                format!("-p tcp --dport {} -j DROP", port),
                format!("-p udp --dport {} -j DROP", port),
            ],
        )?;

        // After applying rules, log full chain contents
        let input_rules = ipt.list("filter", "FORTEXA_INPUT")
            .map_err(|e| format!("List failed: {}", e))?;
        info!("Current FORTEXA_INPUT rules:\n{:?}", input_rules);

        Ok(())
    }

    fn apply_rules<F, G>(
        ipt: &IPTables,
        chain: &str,
        rules: &FirewallDirectionRules,
        ip_rule: F,
        port_rule: G,
    ) -> Result<(), String>
    where
        F: Fn(&Ipv4Addr) -> String,
        G: Fn(&u16) -> Vec<String>,
    {
        // Block IPs
        for ip in &rules.blocked_ips {
            let rule = ip_rule(ip);
            match ipt.append("filter", chain, &rule) {
                Ok(_) => {
                    info!("Applied rule to {}: {}", chain, rule);
                }
                Err(e) => {
                    error!("Failed to apply rule to {} ({}): {}", chain, rule, e);
                }
            }
        }

        // Block ports
        for port in &rules.blocked_ports {
            for rule in port_rule(port) {
                match ipt.append("filter", chain, &rule) {
                    Ok(_) => {
                        info!("Applied rule to {}: {}", chain, rule);
                    }
                    Err(e) => {
                        error!("Failed to apply rule to {} ({}): {}", chain, rule, e);
                    }
                }
            }
        }

        Ok(())
    }


    pub fn delete_rules() -> Result<(), String> {
        let ipt = iptables::new(false).map_err(|e| e.to_string())?;
        ipt.delete("filter", "INPUT", "-j FORTEXA_INPUT").ok();
        ipt.delete("filter", "OUTPUT", "-j FORTEXA_OUTPUT").ok();
        ipt.flush_chain("filter", "FORTEXA_INPUT").ok();
        ipt.flush_chain("filter", "FORTEXA_OUTPUT").ok();
        ipt.delete_chain("filter", "FORTEXA_INPUT").ok();
        ipt.delete_chain("filter", "FORTEXA_OUTPUT").ok();
        Ok(())
    }
}
