use anyhow::Result;
use log::{debug, info};
use std::sync::{Arc, Mutex};

use crate::core::config::Config;
use crate::core::rules::{Rule, RulesManager};
use crate::modules::ModuleManager;
use crate::modules::iptables::IptablesModule;
use crate::modules::logging::LoggingModule;

/// The core firewall engine
#[derive(Clone)]
pub struct Engine {
    /// The configuration
    config: Arc<Config>,

    /// The rules manager
    rules_manager: Arc<RulesManager>,

    /// The module manager
    module_manager: Arc<Mutex<ModuleManager>>,
}

impl Engine {
    /// Create a new engine
    pub fn new(config_path: &str) -> Result<Self> {
        let config = Config::from_file(config_path)?;
        info!("[Engine::new] Loaded config from: {}", config_path);
        info!("[Engine::new] REST port: {}", config.services.rest.port);
        let config = Arc::new(config);

        let rules_manager = Arc::new(RulesManager::new(&config.general.rules_path)?);
        let module_manager = Arc::new(Mutex::new(ModuleManager::new()));

        Ok(Self {
            config,
            rules_manager,
            module_manager,
        })
    }

    /// Register all modules
    pub fn register_all_modules(&self) -> Result<()> {
        let mut module_manager = self.module_manager.lock().unwrap();

        // Register the IPTables module
        if self
            .config
            .modules
            .get("iptables")
            .is_some_and(|m| m.enabled)
        {
            debug!("Registering IPTables module");
            let iptables_module = IptablesModule::new(self.config.clone())?;
            module_manager.register_module("iptables", Box::new(iptables_module))?;
        }

        // Register the Logging module
        if self
            .config
            .modules
            .get("logging")
            .is_some_and(|m| m.enabled)
        {
            debug!("Registering Logging module");
            let logging_module = LoggingModule::new(self.config.clone())?;
            module_manager.register_module("logging", Box::new(logging_module))?;
        }

        Ok(())
    }

    /// Apply all rules
    pub fn apply_rules(&self) -> Result<()> {
        let rules = self.rules_manager.get_enabled_rules()?;

        let module_manager = self.module_manager.lock().unwrap();

        for module_name in module_manager.get_module_names() {
            if let Some(module) = module_manager.get_module(&module_name) {
                debug!("Applying rules to module: {}", module_name);
                module.apply_rules(&rules)?;
            }
        }

        Ok(())
    }

    /// Add a rule
    pub fn add_rule(&self, rule: Rule) -> Result<String> {
        let rule_id = self.rules_manager.add_rule(rule.clone())?;
        self.apply_rules()?;
        Ok(rule_id)
    }

    /// Delete a rule
    pub fn delete_rule(&self, rule_id: &str) -> Result<()> {
        self.rules_manager.delete_rule(rule_id)?;
        self.apply_rules()?;
        Ok(())
    }

    /// Update a rule
    pub fn update_rule(&self, rule: Rule) -> Result<()> {
        self.rules_manager.update_rule(rule)?;
        self.apply_rules()?;
        Ok(())
    }

    /// List all rules
    pub fn list_rules(&self) -> Result<Vec<Rule>> {
        self.rules_manager.list_rules()
    }

    /// Delete all rules
    pub fn reset_rules(&self) -> Result<()> {
        self.rules_manager.reset_rules()?;
        self.apply_rules()?;
        Ok(())
    }

    /// Get a rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Result<Rule> {
        self.rules_manager.get_rule(rule_id)
    }

    /// Get the configuration
    pub fn get_config(&self) -> Arc<Config> {
        self.config.clone()
    }
}
