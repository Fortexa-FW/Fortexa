//! Logging module for the Fortexa firewall

mod logger;

use anyhow::Result;
use std::sync::Arc;

use crate::core::config::Config;
use crate::core::rules::Rule;
use crate::modules::Module;

pub use logger::Logger;

/// Logging module
pub struct LoggingModule {
    /// The configuration
    #[allow(dead_code)]
    config: Arc<Config>,

    /// The logger
    logger: Logger,
}

impl LoggingModule {
    /// Create a new Logging module
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let log_file = config
            .modules
            .get("logging")
            .and_then(|m| m.settings.get("log_file"))
            .and_then(|v| v.as_str())
            .unwrap_or("/var/log/fortexa/firewall.log")
            .to_string();

        let logger = Logger::new(&log_file)?;

        Ok(Self { config, logger })
    }
}

impl Module for LoggingModule {
    fn init(&self) -> Result<()> {
        self.logger.init()
    }

    fn apply_rules(&self, rules: &[Rule]) -> Result<()> {
        // Log the rules being applied
        self.logger.log_rules_applied(rules)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
