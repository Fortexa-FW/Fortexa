use crate::firewall::{
    error::FirewallError, iptables::iptables_impl::IPTablesInterface,
    iptables::iptables_impl::IPTablesWrapper, iptables::iptables_manager::IPTablesManager,
    rules_core::RulesManager,
};
use once_cell::sync::Lazy;
use std::env;

pub struct FirewallManager {
    iptables_mgr: IPTablesManager<IPTablesWrapper>,
}

pub static IPTABLES_TABLE: &str = match option_env!("IPTABLES_TABLE") {
    Some(table) => table,
    None => "filter",
};

pub static USE_IPV6: Lazy<bool> =
    Lazy::new(|| matches!(env::var("USE_IPV6").as_deref(), Ok("true") | Ok("1")));

impl FirewallManager {
    pub fn new() -> Result<Self, FirewallError> {
        let ipt = IPTablesWrapper::new(*USE_IPV6)
            .map_err(|e| FirewallError::ChainError(format!("Wrapper init: {}", e)))?;

        let iptables_mgr = Self::create_iptables_manager(IPTABLES_TABLE, *USE_IPV6, ipt)
            .map_err(|e| FirewallError::ChainError(format!("Manager init: {}", e)))?;

        Ok(Self { iptables_mgr })
    }

    pub fn sync_rules(&mut self, rules: &RulesManager) -> Result<(), FirewallError> {
        self.iptables_mgr.sync_rules(rules.get_iptables_rules())?;
        Ok(())
    }

    pub fn get_iptables_manager(&self) -> &IPTablesManager<IPTablesWrapper> {
        &self.iptables_mgr
    }

    pub fn create_iptables_manager(
        table: &str,
        use_ipv6: bool,
        ipt: IPTablesWrapper,
    ) -> Result<IPTablesManager<IPTablesWrapper>, FirewallError> {
        IPTablesManager::new(table, use_ipv6, ipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iptables_table_default() {
        // Test that the default table is "filter"
        assert_eq!(IPTABLES_TABLE, "filter");
    }

    #[test]
    fn test_firewall_manager_creation() {
        // Test that we can create a firewall manager with the current configuration
        let result = FirewallManager::new();
        match result {
            Ok(_) => {
                // Success case - manager created successfully
                assert!(true);
            }
            Err(e) => {
                // If the error is about chains already existing, that's acceptable
                if e.to_string().contains("Chain already exists") {
                    assert!(true);
                } else {
                    // For any other error, fail the test
                    panic!("Unexpected error: {}", e);
                }
            }
        }
    }

    #[test]
    fn test_get_iptables_manager() {
        let result = FirewallManager::new();
        match result {
            Ok(manager) => {
                let _iptables_mgr = manager.get_iptables_manager();
                // We can verify that we can get the manager, but can't access its internals
                assert!(true);
            }
            Err(e) => {
                // If the error is about chains already existing, that's acceptable
                if e.to_string().contains("Chain already exists") {
                    assert!(true);
                } else {
                    // For any other error, fail the test
                    panic!("Unexpected error: {}", e);
                }
            }
        }
    }
}
