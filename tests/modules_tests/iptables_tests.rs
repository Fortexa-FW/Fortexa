use crate::common::iptables::cleanup_test_chains;
use fortexa::core::rules::{Action, Direction, Rule, RulesManager};
use fortexa::modules::iptables::IptablesFilter;
use serde_json;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
#[ignore]
fn test_iptables_chain_creation() {
    eprintln!("[debug] test_iptables_chain_creation running");
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    eprintln!("[debug] Generated chain prefix: {}", chain_prefix);
    let filter = IptablesFilter::new(&chain_prefix).unwrap();
    eprintln!("[debug] IptablesFilter initialized");
    filter.init().unwrap();
    eprintln!("[debug] filter.init() called");
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] cleanup_test_chains() called");
}

#[test]
#[ignore]
fn test_rule_creation_and_application() {
    eprintln!("[debug] test_rule_creation_and_application running");
    let mut tmpfile = NamedTempFile::new().unwrap();
    write!(tmpfile, "[]").unwrap();
    let rules_path = tmpfile.path().to_str().unwrap();
    eprintln!("[debug] Created temp rules file at: {}", rules_path);
    let rules_manager = RulesManager::new(rules_path).unwrap();
    eprintln!("[debug] RulesManager initialized");
    let rule = Rule::new("test_rule".to_string(), Direction::Input, Action::Accept, 1);
    eprintln!("[debug] Rule created: {:?}", rule);
    let rule_id = rules_manager.add_rule(rule.clone()).unwrap();
    eprintln!("[debug] Rule added with id: {}", rule_id);
    let rules = rules_manager.list_rules().unwrap();
    eprintln!("[debug] Rules after addition: {:?}", rules);
    assert!(rules.iter().any(|r| r.id == rule_id));
    eprintln!("[debug] Assertion passed: rule is present");
    eprintln!("[debug] cleanup_test_chains() called");
}

#[test]
#[ignore]
fn test_custom_chain_creation_and_deletion() {
    eprintln!("[debug] test_custom_chain_creation_and_deletion running");
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    eprintln!(
        "[debug] [test_custom_chain_creation_and_deletion] Generated chain prefix: {}",
        chain_prefix
    );
    let custom_chain = format!("{}_MYCHAIN", chain_prefix);
    eprintln!(
        "[debug] [test_custom_chain_creation_and_deletion] Custom chain name: {}",
        custom_chain
    );
    let builtin_chain = "INPUT";
    eprintln!(
        "[debug] [test_custom_chain_creation_and_deletion] Builtin chain: {}",
        builtin_chain
    );
    let filter = IptablesFilter::new(&chain_prefix).unwrap();
    eprintln!("[debug] [test_custom_chain_creation_and_deletion] IptablesFilter initialized");
    // Create custom chain
    filter
        .create_custom_chain(&custom_chain, Some(builtin_chain))
        .unwrap();
    eprintln!(
        "[debug] [test_custom_chain_creation_and_deletion] Custom chain created: {}",
        custom_chain
    );
    // Try creating again (should be idempotent)
    filter
        .create_custom_chain(&custom_chain, Some(builtin_chain))
        .unwrap();
    eprintln!(
        "[debug] [test_custom_chain_creation_and_deletion] Custom chain creation is idempotent"
    );
    // Delete custom chain
    filter
        .delete_custom_chain(&custom_chain, Some(builtin_chain))
        .unwrap();
    eprintln!(
        "[debug] [test_custom_chain_creation_and_deletion] Custom chain deleted: {}",
        custom_chain
    );
    // Try deleting again (should not panic)
    filter
        .delete_custom_chain(&custom_chain, Some(builtin_chain))
        .unwrap();
    eprintln!(
        "[debug] [test_custom_chain_creation_and_deletion] Custom chain deletion is idempotent"
    );
    // Cleanup all test chains
    crate::common::iptables::cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] [test_custom_chain_creation_and_deletion] cleanup_test_chains() called");
}

#[test]
#[ignore]
fn test_apply_custom_chains_from_file() {
    use fortexa::modules::iptables::filter::{CustomChainEntry, IptablesFilter};
    use std::fs;
    use tempfile::NamedTempFile;

    eprintln!("[debug] test_apply_custom_chains_from_file running");
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    eprintln!(
        "[debug] [test_apply_custom_chains_from_file] Generated chain prefix: {}",
        chain_prefix
    );
    let custom_chain = format!("{}_MYCHAIN", chain_prefix);
    eprintln!(
        "[debug] [test_apply_custom_chains_from_file] Custom chain name: {}",
        custom_chain
    );
    let builtin_chain = "INPUT";
    eprintln!(
        "[debug] [test_apply_custom_chains_from_file] Builtin chain: {}",
        builtin_chain
    );
    // Write a chains.json file with one custom chain entry
    let entry = CustomChainEntry {
        name: custom_chain.clone(),
        reference_from: Some(builtin_chain.to_string()),
    };
    let chains = vec![entry.clone()];
    let tmpfile = NamedTempFile::new().unwrap();
    let chains_path = tmpfile.path().to_str().unwrap().to_string();
    eprintln!(
        "[debug] [test_apply_custom_chains_from_file] Temporary chains.json path: {}",
        chains_path
    );
    fs::write(&chains_path, serde_json::to_string(&chains).unwrap()).unwrap();
    eprintln!(
        "[debug] [test_apply_custom_chains_from_file] chains.json written: {}",
        chains_path
    );
    // Apply custom chains from file
    IptablesFilter::apply_custom_chains_from_file(&chains_path).unwrap();
    eprintln!("[debug] [test_apply_custom_chains_from_file] apply_custom_chains_from_file called");
    // Try again (should be idempotent)
    IptablesFilter::apply_custom_chains_from_file(&chains_path).unwrap();
    eprintln!(
        "[debug] [test_apply_custom_chains_from_file] apply_custom_chains_from_file is idempotent"
    );
    // Cleanup all test chains
    crate::common::iptables::cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] [test_apply_custom_chains_from_file] cleanup_test_chains() called");
}
