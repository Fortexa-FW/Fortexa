use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::core::config::Config;
use crate::core::rules::{Rule, RulesManager};
use crate::modules::ModuleManager;
use crate::modules::logging::LoggingModule;
use crate::modules::netshield::security::NetshieldSecurityConfig;
use crate::modules::netshield::{NetshieldModule, NetshieldRule};

const DEFAULT_CONFIG: &str = r#"
[general]
enabled = true
log_level = "info"

[modules.logging]
enabled = true
settings = { log_file = "/var/log/fortexa.log" }

[modules.netshield]
enabled = true
rules_path = "/var/lib/fortexa/netshield_rules.json"
ebpf_path = "/usr/lib/fortexa/netshield_xdp.o"

[services.rest]
enabled = true
bind_address = "127.0.0.1"
port = 8080
"#;

/// The core firewall engine
pub struct Engine {
    /// The configuration
    config: Arc<Config>,

    /// The rules managers, one per module
    rules_managers: HashMap<String, Arc<RulesManager>>,

    /// The module manager
    pub module_manager: Arc<Mutex<ModuleManager>>,
}

impl Engine {
    /// Create a new engine
    pub fn new(config_path: &str) -> Result<Self> {
        Self::ensure_config_exists(config_path)?;
        let config = Config::from_file(config_path)?;
        info!("[Engine::new] Loaded config from: {}", config_path);
        info!("[Engine::new] REST port: {}", config.services.rest.port);
        let config = Arc::new(config);

        // --- Auto-copy eBPF object to /usr/lib/fortexa/netshield_xdp.o if not present ---
        let ebpf_target = "/usr/lib/fortexa/netshield_xdp.o";
        if let Some(netshield_cfg) = config.modules.get("netshield") {
            let ebpf_path = netshield_cfg.ebpf_path.as_deref().unwrap_or(ebpf_target);
            if ebpf_path == ebpf_target && !std::path::Path::new(ebpf_target).exists() {
                // Try to find the build output eBPF object
                let out_dir = std::env::var("OUT_DIR").ok();
                let build_ebpf = out_dir
                    .as_ref()
                    .map(|d| format!("{}/netshield_xdp.o", d))
                    .filter(|p| std::path::Path::new(p).exists())
                    .or_else(|| {
                        // Fallback to default relative path
                        let fallback = "./netshield_xdp.o";
                        if std::path::Path::new(fallback).exists() {
                            Some(fallback.to_string())
                        } else {
                            None
                        }
                    });
                if let Some(src) = build_ebpf {
                    if let Some(parent) = std::path::Path::new(ebpf_target).parent() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            log::error!("Failed to create directory {}: {}", parent.display(), e);
                        }
                    }
                    match std::fs::copy(&src, ebpf_target) {
                        Ok(_) => log::info!("Copied eBPF object from {} to {}", src, ebpf_target),
                        Err(e) => log::error!(
                            "Failed to copy eBPF object from {} to {}: {}",
                            src,
                            ebpf_target,
                            e
                        ),
                    }
                } else {
                    log::warn!("Could not find eBPF object to copy to {}", ebpf_target);
                }
            }
        }
        // --- End auto-copy ---

        // Create a RulesManager for each module with a rules_path
        let mut rules_managers = HashMap::new();
        for (name, module) in &config.modules {
            let rules_path = module
                .settings
                .get("rules_path")
                .and_then(|v| v.as_str())
                .or({
                    if !module.rules_path.is_empty() {
                        Some(module.rules_path.as_str())
                    } else {
                        None
                    }
                })
                .unwrap_or("");
            if !rules_path.is_empty() {
                rules_managers.insert(name.clone(), Arc::new(RulesManager::new(rules_path)?));
            }
        }
        let module_manager = Arc::new(Mutex::new(ModuleManager::new()));

        Ok(Self {
            config,
            rules_managers,
            module_manager,
        })
    }

    pub fn ensure_config_exists(config_path: &str) -> std::io::Result<()> {
        let config_path = Path::new(config_path);
        if !config_path.exists() {
            if let Some(parent) = config_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = File::create(config_path)?;
            file.write_all(DEFAULT_CONFIG.as_bytes())?;
            println!(
                "Default config created at {}. Please review and edit as needed.",
                config_path.display()
            );
        }
        Ok(())
    }

    /// Register all modules
    pub fn register_all_modules(&self) -> Result<()> {
        let mut module_manager = self.module_manager.lock().unwrap();

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

        // Register the Netshield module
        if self
            .config
            .modules
            .get("netshield")
            .is_some_and(|m| m.enabled)
        {
            debug!("Registering Netshield module");
            let netshield_cfg = self.config.modules.get("netshield").unwrap();
            let rules_path = netshield_cfg
                .settings
                .get("rules_path")
                .and_then(|v| v.as_str())
                .or({
                    if !netshield_cfg.rules_path.is_empty() {
                        Some(netshield_cfg.rules_path.as_str())
                    } else {
                        None
                    }
                })
                .unwrap_or("")
                .to_string();
            let ebpf_path = netshield_cfg.ebpf_path.clone();
            let security_config = NetshieldSecurityConfig::default();
            let rules_manager = self
                .get_rules_manager("netshield")
                .expect("No rules manager for netshield");
            // Try to use eBPF/XDP if the feature is enabled
            #[cfg(feature = "ebpf_enabled")]
            let netshield_module = NetshieldModule::with_xdp_secure(
                rules_path.clone(),
                security_config.clone(),
                rules_manager.clone(),
            ).unwrap_or_else(|e| {
                warn!("Failed to initialize eBPF/XDP: {}. Using basic module.", e);
                NetshieldModule::new(rules_path, security_config, rules_manager)
            });

            // Fallback to basic module if eBPF is not enabled
            #[cfg(not(feature = "ebpf_enabled"))]
            let netshield_module = NetshieldModule::new(
                rules_path,
                security_config,
                rules_manager,
            );
            module_manager.register_module("netshield", Box::new(netshield_module))?;
            info!("[Engine] Netshield module registered.");
        }

        Ok(())
    }

    /// Apply all rules
    pub fn apply_rules(&self) -> Result<()> {
        // Collect module names first to avoid double-locking
        let module_names = {
            let module_manager = self.module_manager.lock().unwrap();
            module_manager.get_module_names()
        };
        // Apply rules to all modules except netshield
        for module_name in &module_names {
            if module_name == "netshield" {
                continue;
            }
            let module_manager = self.module_manager.lock().unwrap();
            if let Some(module) = module_manager.get_module(module_name) {
                debug!("Applying rules to module: {}", module_name);
                let manager = self.rules_managers.get(module_name).cloned();
                if let Some(manager) = manager {
                    module.apply_rules(&manager.get_enabled_rules()?)?;
                }
            }
        }
        // Now, apply rules to netshield (requires mutable access)
        if module_names.iter().any(|n| n == "netshield") {
            // Ensure no other references to self/module_manager are held here
            let mut module_manager = self.module_manager.lock().unwrap();
            if let Some(module) = module_manager.get_module_mut("netshield") {
                if let Some(netshield) = module
                    .as_any_mut()
                    .downcast_mut::<crate::modules::netshield::NetshieldModule>(
                ) {
                    info!("[Engine] Applying all Netshield rules to eBPF/XDP map");
                    match crate::modules::netshield::apply_all_rules(netshield) {
                        Ok(_) => info!("[Engine] Netshield rules applied successfully."),
                        Err(e) => log::error!("[Engine] Failed to apply Netshield rules: {}", e),
                    }
                } else {
                    log::error!("[Engine] Failed to downcast to NetshieldModule");
                }
            } else {
                log::warn!(
                    "[Engine] Netshield XDP is not attached; rules not applied to eBPF/XDP."
                );
            }
        }
        Ok(())
    }

    /// Helper to get a rules manager for a module
    pub fn get_rules_manager(&self, module: &str) -> Option<Arc<RulesManager>> {
        self.rules_managers.get(module).cloned()
    }

    /// Add a rule
    pub fn add_rule(&self, module: &str, rule: Rule) -> Result<String> {
        let manager = self
            .get_rules_manager(module)
            .ok_or_else(|| anyhow::anyhow!("No rules manager for module: {}", module))?;
        let rule_id = manager.add_rule(rule.clone())?;
        self.apply_rules()?;
        Ok(rule_id)
    }

    /// Delete a rule
    pub fn delete_rule(&self, module: &str, rule_id: &str) -> Result<()> {
        let manager = self
            .get_rules_manager(module)
            .ok_or_else(|| anyhow::anyhow!("No rules manager for module: {}", module))?;
        manager.delete_rule(rule_id)?;
        self.apply_rules()?;
        Ok(())
    }

    /// Update a rule
    pub fn update_rule(&self, module: &str, rule: Rule) -> Result<()> {
        let manager = self
            .get_rules_manager(module)
            .ok_or_else(|| anyhow::anyhow!("No rules manager for module: {}", module))?;
        manager.update_rule(rule)?;
        self.apply_rules()?;
        Ok(())
    }

    /// List all rules
    pub fn list_rules(&self, module: &str) -> Result<Vec<Rule>> {
        let manager = self
            .get_rules_manager(module)
            .ok_or_else(|| anyhow::anyhow!("No rules manager for module: {}", module))?;
        manager.list_rules()
    }

    /// Delete all rules
    pub fn reset_rules(&self, module: &str) -> Result<()> {
        let manager = self
            .get_rules_manager(module)
            .ok_or_else(|| anyhow::anyhow!("No rules manager for module: {}", module))?;
        manager.reset_rules()?;
        self.apply_rules()?;
        Ok(())
    }

    /// Get a rule by ID
    pub fn get_rule(&self, module: &str, rule_id: &str) -> Result<Rule> {
        let manager = self
            .get_rules_manager(module)
            .ok_or_else(|| anyhow::anyhow!("No rules manager for module: {}", module))?;
        manager.get_rule(rule_id)
    }

    /// Get the configuration
    pub fn get_config(&self) -> Arc<Config> {
        self.config.clone()
    }

    pub fn module_manager(&self) -> &Arc<Mutex<ModuleManager>> {
        &self.module_manager
    }
}

/// Apply a single NetshieldRule to the system (placeholder for eBPF/XDP logic)
pub fn apply_rule_to_system(rule: &NetshieldRule) -> Result<(), String> {
    // TODO: Replace this with real eBPF/XDP logic
    info!(
        "[Netshield] Applying rule: id={} name={} action={:?} direction={:?} src={:?} dst={:?} group={:?}",
        rule.id, rule.name, rule.action, rule.direction, rule.source, rule.destination, rule.group
    );
    Ok(())
}
