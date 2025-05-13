use anyhow::{Context, Result};
use serde_json;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::Path;

use crate::core::rules::Rule;

/// File-based database for storing rules
pub struct FileDB {
    /// The path to the database file
    path: String,

    /// The rules stored in memory
    rules: HashMap<String, Rule>,
}

impl FileDB {
    /// Create a new file database
    pub fn new(path: &str) -> Result<Self> {
        // Ensure the directory exists
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)
                .context(format!("Failed to create directory: {}", parent.display()))?;
        }

        let mut db = Self {
            path: path.to_string(),
            rules: HashMap::new(),
        };

        // Load rules from the file if it exists
        if Path::new(path).exists() {
            db.load()?;
        } else {
            // Create an empty file
            db.save()?;
        }

        Ok(db)
    }
    
    /// Load rules from the file
    fn load(&mut self) -> Result<()> {
        let file = File::open(&self.path)
            .context(format!("Failed to open rules file: {}", self.path))?;

        let reader = BufReader::new(file);

        let rules: Vec<Rule> = serde_json::from_reader(reader)
            .context(format!("Failed to parse rules file: {}", self.path))?;

        self.rules.clear();
        for rule in rules {
            self.rules.insert(rule.id.clone(), rule);
        }

        Ok(())
    }

    /// Save rules to the file
    fn save(&self) -> Result<()> {
        let rules: Vec<Rule> = self.rules.values().cloned().collect();

        let json = serde_json::to_string_pretty(&rules)
            .context("Failed to serialize rules")?;

        let mut file = File::create(&self.path)
            .context(format!("Failed to create rules file: {}", self.path))?;

        file.write_all(json.as_bytes())
            .context(format!("Failed to write rules to file: {}", self.path))?;

        Ok(())
    }

    /// Add a rule to the database
    pub fn add_rule(&mut self, rule: Rule) -> Result<String> {
        let id = rule.id.clone();
        self.rules.insert(id.clone(), rule);
        self.save()?;
        Ok(id)
    }

    /// Get a rule from the database
    pub fn get_rule(&self, id: &str) -> Result<Rule> {
        self.rules.get(id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Rule not found: {}", id))
    }

    /// Update a rule in the database
    pub fn update_rule(&mut self, rule: Rule) -> Result<()> {
        if !self.rules.contains_key(&rule.id) {
            return Err(anyhow::anyhow!("Rule not found: {}", rule.id));
        }

        self.rules.insert(rule.id.clone(), rule);
        self.save()?;
        Ok(())
    }

    /// Delete a rule from the database
    pub fn delete_rule(&mut self, id: &str) -> Result<()> {
        if !self.rules.contains_key(id) {
            return Err(anyhow::anyhow!("Rule not found: {}", id));
        }

        self.rules.remove(id);
        self.save()?;
        Ok(())
    }

    /// List all rules in the database
    pub fn list_rules(&self) -> Result<Vec<Rule>> {
        let mut rules: Vec<Rule> = self.rules.values().cloned().collect();

        // Sort by priority
        rules.sort_by(|a, b| a.priority.cmp(&b.priority));

        Ok(rules)
    }

    /// Delete all rules in the database
    pub fn reset_rules(&mut self) -> Result<()> {
        self.rules.clear();
        self.save()?;

        Ok(())
    }
}
