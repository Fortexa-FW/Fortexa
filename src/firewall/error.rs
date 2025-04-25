use std::fmt;

#[derive(Debug)]
pub enum FirewallError {
    IPTablesError(String),
    ChainError(String),
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewallError::IPTablesError(e) => write!(f, "IPTables error: {}", e),
            FirewallError::ChainError(e) => write!(f, "Chain error: {}", e),
        }
    }
}

impl std::error::Error for FirewallError {}

impl From<String> for FirewallError {
    fn from(e: String) -> Self {
        FirewallError::ChainError(e)
    }
}
