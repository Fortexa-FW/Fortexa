use fortexa::modules::iptables::IptablesFilter;

/// Cleans up iptables chains created for tests with the given prefix.
pub fn cleanup_test_chains(chain_prefix: &str) {
    let filter = IptablesFilter::new(chain_prefix)
        .expect("Failed to create IptablesFilter for cleanup");
    filter.cleanup().expect("Failed to cleanup iptables test chains");
} 