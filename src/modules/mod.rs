//! Firewall modules

use anyhow::Result;
use std::collections::HashMap;

use crate::core::rules::Rule;

pub mod logging;
pub mod netshield;

/// Module trait
pub trait Module: Send + Sync {
    /// Initialize the module
    fn init(&self) -> Result<()>;

    /// Apply rules to the module
    fn apply_rules(&self, rules: &[Rule]) -> Result<()>;

    /// For downcasting
    fn as_any(&self) -> &dyn std::any::Any;

    /// For mutable downcasting
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// Module manager
pub struct ModuleManager {
    /// Registered modules
    modules: HashMap<String, Box<dyn Module>>,
}

impl ModuleManager {
    /// Create a new module manager
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Register a module
    pub fn register_module(&mut self, name: &str, module: Box<dyn Module>) -> Result<()> {
        module.init()?;
        self.modules.insert(name.to_string(), module);
        Ok(())
    }

    /// Get a module by name
    pub fn get_module(&self, name: &str) -> Option<&dyn Module> {
        self.modules.get(name).map(|m| m.as_ref())
    }

    /// Get a mutable module by name
    pub fn get_module_mut(&mut self, name: &str) -> Option<&mut Box<dyn Module>> {
        self.modules.get_mut(name)
    }

    /// Get all module names
    pub fn get_module_names(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }
}

impl Default for ModuleManager {
    fn default() -> Self {
        Self::new()
    }
}
