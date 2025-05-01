use iptables::IPTables;
use std::sync::Arc;

pub trait IPTablesInterface: Send + Sync {
    fn new(use_ipv6: bool) -> Result<Self, String>
    where
        Self: Sized;
    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), String>;
    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), String>;
    fn new_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn insert(&self, table: &str, chain: &str, rule: &str, position: usize) -> Result<(), String>;
    fn flush_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), String>;
    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, String>;
    fn batch_execute(&self, commands: &[String]) -> Result<(), String>;
}

#[derive(Clone)]
pub struct IPTablesWrapper(pub Arc<IPTables>);

impl IPTablesInterface for IPTablesWrapper {
    fn new(use_ipv6: bool) -> Result<Self, String> {
        iptables::new(use_ipv6)
            .map(|inner| IPTablesWrapper(Arc::new(inner)))
            .map_err(|e| e.to_string())
    }

    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), String> {
        self.0.append(table, chain, rule).map_err(|e| e.to_string())
    }

    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), String> {
        self.0.delete(table, chain, rule).map_err(|e| e.to_string())
    }

    fn new_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.new_chain(table, chain).map_err(|e| e.to_string())
    }

    fn insert(&self, table: &str, chain: &str, rule: &str, position: usize) -> Result<(), String> {
        self.0
            .insert(table, chain, rule, position.try_into().unwrap())
            .map_err(|e| e.to_string())
    }

    fn flush_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.flush_chain(table, chain).map_err(|e| e.to_string())
    }

    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), String> {
        self.0.delete_chain(table, chain).map_err(|e| e.to_string())
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, String> {
        self.0.list(table, chain).map_err(|e| e.to_string())
    }

    fn batch_execute(&self, commands: &[String]) -> Result<(), String> {
        let temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| format!("Temp file creation failed: {}", e))?;

        std::fs::write(temp_file.path(), commands.join("\n"))
            .map_err(|e| format!("Batch write failed: {}", e))?;

        std::process::Command::new("iptables-restore")
            .arg(temp_file.path())
            .status()
            .map_err(|e| format!("Batch execute failed: {}", e))?;

        Ok(())
    }
}
