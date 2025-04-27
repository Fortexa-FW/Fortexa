use crate::{
    firewall::{
        error::FirewallError,
        rules::IPTablesRuleSet,
    },
    RULES_FILE,
};

pub struct RulesManager {
    iptables_rules: IPTablesRuleSet,
}

impl RulesManager {
    pub fn new() -> Result<Self, FirewallError> {
        let rules = IPTablesRuleSet::load_from_file(RULES_FILE);
        
        Ok(Self {
            rules
        })
    }

    pub fn get_iptables_rules(&self) -> &IPTablesRuleSet {
        &self.iptables_rules
    }

}
