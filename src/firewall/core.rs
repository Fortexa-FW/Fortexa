use crate::{
    firewall::{
        error::FirewallError,
        iptables::iptables_manager::IPTablesManager,
        iptables::iptables::IPTablesInterface,
        iptables::iptables::IPTablesWrapper,
        iptables::rules::IPTablesRuleSet,
    },
};
use std::env;
use once_cell::sync::Lazy;

pub struct FirewallManager {
    iptables_mgr: IPTablesManager<IPTablesWrapper>,
}

pub static IPTABLES_TABLE: &str = match option_env!("IPTABLES_TABLE") {
    Some(table) => table,
    None => "filter",
};

pub static USE_IPV6: Lazy<bool> = Lazy::new(|| {
    matches!(
        env::var("USE_IPV6").as_deref(),
        Ok("true") | Ok("1")
    )
});

impl FirewallManager {
    pub fn new() -> Result<Self, FirewallError> {
        let ipt = IPTablesWrapper::new(*USE_IPV6)
            .map_err(|e| FirewallError::ChainError(format!("Wrapper init: {}", e)))?;

        let iptables_mgr = Self::create_iptables_manager(IPTABLES_TABLE, *USE_IPV6, ipt);
        
        Ok(Self {
            iptables_mgr
        })
    }

    pub fn sync_rules(&mut self, rules: &IPTablesRuleSet) -> Result<(), FirewallError> {
        self.iptables_mgr.sync_rules(rules)?;
        Ok(())
    }

    pub fn get_iptables_manager(&self) -> &IPTablesManager<IPTablesWrapper> {
        &self.iptables_mgr
    }

    pub fn create_iptables_manager(
        table: &str,
        use_ipv6: bool,
        ipt: IPTablesWrapper
    ) -> &IPTablesManager<IPTablesWrapper> {
        IPTablesManager::new(table, use_ipv6, ipt)
    }

}
