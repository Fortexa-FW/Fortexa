//! IPTables module for the Fortexa firewall

pub mod filter;

use anyhow::Result;
use std::sync::Arc;

use crate::core::config::Config;
use crate::core::rules::Rule;
use crate::modules::Module;

pub use filter::IptablesFilter;

/// IPTables module
pub struct IptablesModule {
    /// The configuration
    #[allow(dead_code)]
    config: Arc<Config>,

    /// The IPTables filter
    filter: IptablesFilter,
}

impl IptablesModule {
    /// Create a new IPTables module
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let chain_prefix = config
            .modules
            .get("iptables")
            .and_then(|m| m.settings.get("chain_prefix"))
            .and_then(|v| v.as_str())
            .unwrap_or("FORTEXA")
            .to_string();

        let filter = IptablesFilter::new(&chain_prefix)?;

        Ok(Self { config, filter })
    }
}

impl Module for IptablesModule {
    fn init(&self) -> Result<()> {
        self.filter.init()?;
        let chains_path = self
            .config
            .modules
            .get("iptables")
            .and_then(|m| m.settings.get("chains_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("/var/lib/fortexa/chains.json");
        crate::modules::iptables::filter::IptablesFilter::apply_custom_chains_from_file(
            chains_path,
        )?;
        Ok(())
    }

    fn apply_rules(&self, rules: &[Rule]) -> Result<()> {
        self.filter.apply_rules(rules)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl IptablesModule {
    pub fn apply_rules_with_auto_create(
        &self,
        rules: &[crate::core::rules::Rule],
        auto_create_chain: bool,
    ) -> Result<()> {
        self.filter
            .apply_rules_with_auto_create(rules, auto_create_chain)
    }
}
