use crate::rules::{FirewallDirectionRules, FirewallRuleSet};
use ipnetwork::Ipv4Network;
use iptables::IPTables;
use log::{debug, info}; // info, error, debug, warn if needed
use mockall::automock;

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

#[automock]
pub trait IPTablesInterface {
    fn new(use_ipv6: bool) -> Result<Self, String> where Self: Sized;
    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), String>;
    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), String>;
    fn new_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn insert(&self, table: &str, chain: &str, rule: &str, position: usize) -> Result<(), String>;
    fn flush_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, String>;
    fn batch_execute(&self, commands: &[String]) -> Result<(), String>;
}

pub struct IPTablesWrapper(pub IPTables);

impl IPTablesInterface for IPTablesWrapper {
    fn new(use_ipv6: bool) -> Result<Self, String> {  
        iptables::new(use_ipv6)  
            .map(|inner| IPTablesWrapper(inner))  
            .map_err(|e| e.to_string())  
    }

    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), String> {
        self.0.append(table, chain, rule)
            .map_err(|e| e.to_string())
    }

    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), String> {
        self.0.delete(table, chain, rule)
            .map_err(|e| e.to_string())
    }

    fn new_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.new_chain(table, chain)
            .map_err(|e| e.to_string())
    }

    fn insert(&self, table: &str, chain: &str, rule: &str, position: usize) -> Result<(), String> {
        self.0.insert(table, chain, rule, position.try_into().unwrap())
            .map_err(|e| e.to_string())
    }

    fn flush_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.flush_chain(table, chain)
            .map_err(|e| e.to_string())
    }

    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.delete_chain(table, chain)
            .map_err(|e| e.to_string())
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, String> {
        self.0.list(table, chain)
            .map_err(|e| e.to_string())
    }


    fn batch_execute(&self, commands: &[String]) -> Result<(), String> {  
        let temp_file = tempfile::NamedTempFile::new()  
            .map_err(|e| format!("Temp file creation failed: {}", e))?;  

        std::fs::write(temp_file.path(), commands.join("\n"))  
            .map_err(|e| format!("Batch write failed: {}", e))?;  

        std::process::Command::new("iptables-restore")  
            .arg(temp_file.path())  
            .status()  
            .map_err(|e| format!("Batch execute failed: {}", e))?;  

        Ok(())  
    } 
}

pub struct FirewallManager<T: IPTablesInterface = IPTablesWrapper> {
    table: String,
    use_ipv6: bool,
    ipt: T,
}


impl<T: IPTablesInterface> FirewallManager<T> {
    pub fn new(table: &str, use_ipv6: bool, ipt: T) -> Result<Self, FirewallError> {
        //let ipt = iptables::new(use_ipv6).map_err(|e| FirewallError::IPTablesError(e.to_string()))?;

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
            ipt,
        })
    }

    pub fn sync_rules(&self, rules: &FirewallRuleSet) -> Result<(), FirewallError> {
        let ipt = iptables::new(self.use_ipv6)
            .map_err(|e| FirewallError::IPTablesError(e.to_string()))?;

        debug!("Syncing rules to table {}", self.table);
        debug!("Input IPs: {:?}", rules.input.blocked_ips);
        debug!("Input Ports: {:?}", rules.input.blocked_ports);

        // Clear existing rules
        self.ipt.flush_chain(&self.table, "FORTEXA_INPUT")
            .map_err(|e| FirewallError::ChainError(format!("Flush INPUT: {}", e)))?;
        self.ipt.flush_chain(&self.table, "FORTEXA_OUTPUT")
            .map_err(|e| FirewallError::ChainError(format!("Flush OUTPUT: {}", e)))?;

        // INPUT rules
        Self::apply_rules(
            self,
            &self.ipt,
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
            self,
            &self.ipt,
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
        &self,
        ipt: &dyn IPTablesInterface,
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
        let mut batch = Vec::new();

        // 1. Add table declaration and chain initialization
        batch.push(format!("*{}", table));
        batch.push(format!(":{} - [0:0]", chain));  // Chain declaration with default policy
        
        // 2. Format rules with chain context
        let format_rule = |rule: String| format!("-A {} {}", chain, rule);
        
        // Whitelisted IPs
        rules.whitelisted_ips.iter()
            .map(|ip| ip_rule(ip, "ACCEPT"))
            .map(format_rule)
            .for_each(|r| batch.push(r));
        
        // Whitelisted ports 
        rules.whitelisted_ports.iter()
            .flat_map(|port| port_rule(port, "ACCEPT"))
            .map(format_rule)
            .for_each(|r| batch.push(r));
        
        // Blocked IPs
        rules.blocked_ips.iter()
            .filter(|ip| !rules.whitelisted_ips.contains(ip))
            .map(|ip| ip_rule(ip, "DROP"))
            .map(format_rule)
            .for_each(|r| batch.push(r));
        
        // Blocked ports
        rules.blocked_ports.iter()
            .filter(|port| !rules.whitelisted_ports.contains(port))
            .flat_map(|port| port_rule(port, "DROP"))
            .map(format_rule)
            .for_each(|r| batch.push(r));
        
        // 3. Add commit marker
        batch.push("COMMIT".to_string());
        
        // 4. Execute atomic batch
        ipt.batch_execute(&batch)
            .map_err(|e| FirewallError::ChainError(format!("Batch failed for {}/{}: {}", table, chain, e)))?;
    
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

    fn delete_chains(ipt: &dyn IPTablesInterface, table: &str) -> Result<(), FirewallError> {
        ipt.delete(table, "INPUT", "-j FORTEXA_INPUT").ok();
        ipt.delete(table, "OUTPUT", "-j FORTEXA_OUTPUT").ok();
        ipt.flush_chain(table, "FORTEXA_INPUT").ok();
        ipt.flush_chain(table, "FORTEXA_OUTPUT").ok();
        ipt.delete_chain(table, "FORTEXA_INPUT").ok();
        ipt.delete_chain(table, "FORTEXA_OUTPUT").ok();
        Ok(())
    }

    pub fn allow_established(&self) -> Result<(), FirewallError> {  
        self.ipt.append(  
            "filter",  
            "FORTEXA_INPUT",  
            "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"  
        )
            .map_err(|e| FirewallError::ChainError(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use mockall::predicate::*;

    fn sample_rules() -> FirewallRuleSet {
        FirewallRuleSet {
            table: FromStr::from_str("filter"),
            input: FirewallDirectionRules {
                blocked_ips: [Ipv4Network::from_str("192.168.1.100/32").unwrap()].into(),
                blocked_ports: [22].into(),
                whitelisted_ips: [Ipv4Network::from_str("10.0.0.5/32").unwrap()].into(),
                whitelisted_ports: [443].into(),
            },
            output: FirewallDirectionRules::default(),
        }
    }

    #[test]
    fn test_new_firewall_manager_success() {
        let mut mock = MockIPTablesInterface::new(false).unwrap();
        
        mock.expect_new_chain()
            .with(eq("filter"), eq("FORTEXA_INPUT"))
            .times(1)
            .returning(|_, _| Ok(()));
            
        mock.expect_new_chain()
            .with(eq("filter"), eq("FORTEXA_OUTPUT"))
            .times(1)
            .returning(|_, _| Ok(()));

        mock.expect_insert()
            .with(eq("filter"), eq("INPUT"), eq("-j FORTEXA_INPUT"), eq(1))
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        mock.expect_insert()
            .with(eq("filter"), eq("OUTPUT"), eq("-j FORTEXA_OUTPUT"), eq(1))
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let manager = FirewallManager::new("filter", false, mock);
        assert!(manager.is_ok());
    }

    #[test]
    #[ignore = "requires root privileges"]
    fn live_firewall_test() {
        let ipt = IPTablesWrapper::new(false).unwrap();
        let manager = FirewallManager::new("filter", false, ipt).unwrap();
    }
}