//! IPTables module for the Fortexa firewall

mod filter;

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

        Ok(Self {
            config,
            filter,
        })
    }
}

impl Module for IptablesModule {
    fn init(&self) -> Result<()> {
        self.filter.init()
    }

    fn apply_rules(&self, rules: &[Rule]) -> Result<()> {
        self.filter.apply_rules(rules)
    }
}
