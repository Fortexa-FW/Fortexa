use anyhow::{Context, Result};
use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::core::rules::Rule;

/// Logger
pub struct Logger {
    /// The log file path
    #[allow(dead_code)]
    log_file: String,

    /// The log file handle
    file: Arc<Mutex<File>>,
}

impl Logger {
    /// Create a new logger
    pub fn new(log_file: &str) -> Result<Self> {
        // Ensure the directory exists
        if let Some(parent) = Path::new(log_file).parent() {
            std::fs::create_dir_all(parent).context(format!(
                "Failed to create log directory: {}",
                parent.display()
            ))?;
        }

        // Open or create the log file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .context(format!("Failed to open log file: {}", log_file))?;

        Ok(Self {
            log_file: log_file.to_string(),
            file: Arc::new(Mutex::new(file)),
        })
    }

    /// Initialize the logger
    pub fn init(&self) -> Result<()> {
        self.log(&format!(
            "Fortexa firewall logger initialized at {}",
            Local::now()
        ))
    }

    /// Log a message
    pub fn log(&self, message: &str) -> Result<()> {
        let mut file = self.file.lock().unwrap();
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(file, "[{}] {}", timestamp, message).context("Failed to write to log file")?;

        Ok(())
    }

    /// Log rules being applied
    pub fn log_rules_applied(&self, rules: &[Rule]) -> Result<()> {
        self.log(&format!("Applying {} rules", rules.len()))?;

        for rule in rules {
            if rule.enabled == 1 {
                self.log(&format!(
                    "Applied rule {}: {} (action: {:?})",
                    rule.id, rule.name, rule.action
                ))?;
            }
        }

        Ok(())
    }
}
