use crate::{
    RULES_FILE,
    firewall::{error::FirewallError, iptables::rules::IPTablesRuleSet},
};

pub struct RulesManager {
    iptables_rules: IPTablesRuleSet,
}

impl RulesManager {
    pub fn new() -> Result<Self, FirewallError> {
        let iptables_rules = IPTablesRuleSet::load_from_file(RULES_FILE);

        Ok(Self { iptables_rules })
    }

    pub fn get_iptables_rules(&self) -> &IPTablesRuleSet {
        &self.iptables_rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_manager_creation() {
        let result = RulesManager::new();
        assert!(result.is_ok());
    }

    #[test]
    fn test_rules_file_env_var() {
        // Test default value
        assert_eq!(RULES_FILE, "rules.json");

        // Note: We can't easily test the case where RULES_FILE is set
        // because it's set at compile time with option_env!
    }

    #[test]
    fn test_get_iptables_rules() {
        let rules_manager = RulesManager::new().unwrap();
        let _rules = rules_manager.get_iptables_rules();
        // We can't easily test the contents of the rules without knowing the IPTablesRuleSet implementation
    }
}
