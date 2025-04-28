use iptables::IPTables;
use std::sync::Arc;

pub trait IPTablesInterface: Send + Sync {
    fn new(use_ipv6: bool) -> Result<Self, String>
    where
        Self: Sized;
    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), String>;
    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), String>;
    fn new_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn insert(&self, table: &str, chain: &str, rule: &str, position: usize) -> Result<(), String>;
    fn flush_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, String>;
    fn batch_execute(&self, commands: &[String]) -> Result<(), String>;
}

#[derive(Clone)]
pub struct IPTablesWrapper(pub Arc<IPTables>);

impl IPTablesInterface for IPTablesWrapper {
    fn new(use_ipv6: bool) -> Result<Self, String> {
        iptables::new(use_ipv6)
            .map(|inner| IPTablesWrapper(Arc::new(inner)))
            .map_err(|e| e.to_string())
    }

    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), String> {
        self.0.append(table, chain, rule).map_err(|e| e.to_string())
    }

    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), String> {
        self.0.delete(table, chain, rule).map_err(|e| e.to_string())
    }

    fn new_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.new_chain(table, chain).map_err(|e| e.to_string())
    }

    fn insert(&self, table: &str, chain: &str, rule: &str, position: usize) -> Result<(), String> {
        self.0
            .insert(table, chain, rule, position.try_into().unwrap())
            .map_err(|e| e.to_string())
    }

    fn flush_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.flush_chain(table, chain).map_err(|e| e.to_string())
    }

    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.delete_chain(table, chain).map_err(|e| e.to_string())
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, String> {
        self.0.list(table, chain).map_err(|e| e.to_string())
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

#[cfg(test)]
mod tests {
    use crate::firewall::{FirewallError, IPTablesManager, iptables::rules::IPTablesRuleSet};

    use super::*;

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

        fn create_manager(&self) -> Result<IPTablesManager<IPTablesWrapper>, FirewallError> {
            IPTablesManager::new(&self.table, false, self.ipt.clone())
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

        let _manager = env.create_manager()?; //FIXME: Handle error properly

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

        let mut rules = IPTablesRuleSet::default();
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
        let mut rules = IPTablesRuleSet::default();
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

        let mut rules = IPTablesRuleSet::default();
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
