use fortexa::firewall::core::FirewallManager;

#[tokio::test]
async fn test_firewall_initialization() {
    // Test firewall manager initialization
    let result = FirewallManager::new();
    match result {
        Ok(_) => {
            // Success case
            assert!(true);
        }
        Err(e) if e.to_string().contains("Chain already exists") => {
            // Acceptable error case
            assert!(true);
        }
        Err(e) => {
            // Unexpected error
            panic!("Unexpected error: {}", e);
        }
    }
}

#[tokio::test]
async fn test_firewall_rules_sync() {
    let firewall_result = FirewallManager::new();
    let rules_result = fortexa::firewall::rules_core::RulesManager::new();

    match (firewall_result, rules_result) {
        (Ok(mut firewall), Ok(rules)) => {
            // Test syncing rules to the firewall
            let result = firewall.sync_rules(&rules);
            assert!(result.is_ok(), "Rules should sync successfully");
        }
        (Err(firewall_err), _) if firewall_err.to_string().contains("Chain already exists") => {
            // Acceptable error case for firewall
            assert!(true);
        }
        (_, Err(rules_err)) if rules_err.to_string().contains("Chain already exists") => {
            // Acceptable error case for rules
            assert!(true);
        }
        (Err(e), _) | (_, Err(e)) => {
            // Unexpected error
            panic!("Unexpected error: {}", e);
        }
    }
} 