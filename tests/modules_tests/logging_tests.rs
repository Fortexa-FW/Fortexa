use fortexa::modules::logging::Logger;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_logger_functionality() {
    eprintln!("[debug] test_logger_functionality running");
    let tmpfile = NamedTempFile::new().unwrap();
    let log_path = tmpfile.path().to_str().unwrap();
    eprintln!("[debug] Created temp log file at: {}", log_path);
    let logger = Logger::new(log_path).unwrap();
    eprintln!("[debug] Logger initialized");
    logger.init().unwrap();
    eprintln!("[debug] Logger init() called");
    logger.log("Test log entry").unwrap();
    eprintln!("[debug] Log entry written: Test log entry");
    let contents = fs::read_to_string(log_path).unwrap();
    eprintln!("[debug] Log file contents: {}", contents);
    assert!(contents.contains("Test log entry"));
    eprintln!("[debug] Assertion passed: log file contains entry");
}
