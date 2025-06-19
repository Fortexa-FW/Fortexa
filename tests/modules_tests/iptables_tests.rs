use fortexa::core::rules::{Action, Direction, Rule, RulesManager};
use fortexa::modules::iptables::IptablesFilter;
use std::io::Write;
use tempfile::NamedTempFile;

fn cleanup_test_chains(chain_prefix: &str) {
    let filter = IptablesFilter::new(chain_prefix)
        .expect("Failed to create IptablesFilter for cleanup");
    filter.cleanup().expect("Failed to cleanup iptables test chains");
}


#[test]
fn test_iptables_chain_creation() {
    eprintln!("[debug] test_iptables_chain_creation running");
    let chain_prefix = format!("TST{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    eprintln!("[debug] Generated chain prefix: {}", chain_prefix);
    let filter = IptablesFilter::new(&chain_prefix).unwrap();
    eprintln!("[debug] IptablesFilter initialized");
    filter.init().unwrap();
    eprintln!("[debug] filter.init() called");
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] cleanup_test_chains() called");
}

#[test]
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
    let chain_prefix = "TST..."; // use the actual prefix if known
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] cleanup_test_chains() called");
}
