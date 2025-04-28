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
