use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Configuration for the Fortexa firewall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// General configuration
    pub general: GeneralConfig,

    /// Module-specific configurations
    pub modules: HashMap<String, ModuleConfig>,

    /// Service configurations
    pub services: ServiceConfig,
}

/// General configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Whether the firewall is enabled
    pub enabled: bool,

    /// The log level
    pub log_level: String,
}

/// Module-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    /// Whether the module is enabled
    pub enabled: bool,

    /// Module-specific settings
    #[serde(flatten)]
    pub settings: HashMap<String, serde_json::Value>,

    /// The rules storage path (optional only for module who need)
    #[serde(default)]
    pub rules_path: String,

    /// Optional eBPF object path for netshield (only used for netshield)
    #[serde(default)]
    pub ebpf_path: Option<String>,
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// REST API configuration
    pub rest: RestConfig,
}

/// REST API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestConfig {
    /// Whether the REST API is enabled
    pub enabled: bool,

    /// The binding address for the REST API
    pub bind_address: String,

    /// The port for the REST API
    pub port: u16,
}

impl Config {
    /// Load the configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut file = File::open(path)
            .with_context(|| format!("Failed to open config file: {}", path.display()))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config = match path.extension().and_then(|ext| ext.to_str()) {
            Some("toml") => config::Config::builder()
                .add_source(config::File::from_str(&contents, config::FileFormat::Toml))
                .build()?,
            Some("json") => config::Config::builder()
                .add_source(config::File::from_str(&contents, config::FileFormat::Json))
                .build()?,
            _ => return Err(anyhow::anyhow!("Unsupported config file format")),
        };

        let config: Self = config.try_deserialize()?;
        Ok(config)
    }

    /// Get the default configuration
    pub fn get_default_configuration() -> Self {
        Self {
            general: GeneralConfig {
                enabled: true,
                log_level: "info".to_string(),
            },
            modules: HashMap::from([
                (
                    "logging".to_string(),
                    ModuleConfig {
                        enabled: true,
                        settings: HashMap::from([(
                            "log_file".to_string(),
                            serde_json::Value::String("/var/log/fortexa/firewall.log".to_string()),
                        )]),
                        rules_path: "".to_string(),
                        ebpf_path: None,
                    },
                ),
                (
                    "netshield".to_string(),
                    ModuleConfig {
                        enabled: true,
                        settings: HashMap::from([(
                            "rules_path".to_string(),
                            serde_json::Value::String(
                                "/var/lib/fortexa/netshield_rules.json".to_string(),
                            ),
                        )]),
                        rules_path: "".to_string(),
                        ebpf_path: Some("/usr/lib/fortexa/netshield_xdp.o".to_string()),
                    },
                ),
            ]),
            services: ServiceConfig {
                rest: RestConfig {
                    enabled: true,
                    bind_address: "127.0.0.1".to_string(),
                    port: 8080,
                },
            },
        }
    }
}
