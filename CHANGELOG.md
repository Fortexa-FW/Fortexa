# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **eBPF Integration**: Complete migration from iptables to eBPF-based packet filtering
  - Added XDP (eXpress Data Path) program for high-performance packet processing
  - Integrated aya-ebpf framework for modern eBPF development
  - Added comprehensive security module with privilege controls and validation
  - Implemented conditional compilation with `ebpf_enabled` feature flag
- **Network Types Upgrade**: Updated to network-types 0.0.8 for latest protocol support
  - Enhanced packet parsing with improved API compatibility
  - Added manual parsing for alignment-safe packet processing
  - Differentiated handling for TCP (u16) vs UDP ([u8;2]) field types
- **Build System Enhancements**:
  - Intelligent eBPF build script with existing object detection
  - Graceful fallback when eBPF compilation is unavailable
  - Cross-platform build support with Linux target detection
  - Automatic eBPF object copying to build output directory

### Changed

- **Rust Edition Upgrade**: Migrated all projects to Rust 2024 edition
  - Updated fortexa, netshield-ebpf, and netshield-ebpf-common projects
  - Synchronized rustfmt configurations across all projects
  - Enhanced language features and improved diagnostics
- **Dependency Modernization**: Upgraded to latest stable eBPF dependencies
  - aya-ebpf: git versions → 0.1 stable release
  - aya-ebpf-macros, aya-log-ebpf: stable versions for production use
  - Eliminated nightly-only dependencies for better stability
- **Code Quality Improvements**: Applied clippy suggestions and best practices
  - Replaced manual range checks with idiomatic `RangeInclusive::contains()`
  - Removed needless borrows in build scripts
  - Eliminated dead code and unused constants
- Implement use of iptables to block IP and/or ports
- Add some loggers with events type info,debug,error,warn
- Rules API to create and get rules
- Monitore all of network interface except lo
- Add the possibility to whitelist IP and/or ports
- CI (rust format + CHANGELOG checks)
- Permit to partially update the rules
- Add possibility to specify the netmask for the rules (eg. x.x.x.x/x)
- Add documentation for API
- Add new API endpoints
- Add reset endpoint to clear iptables only
- New templates for issues (bug\_report, documentation, enhancement, features)
- New DEVELOPMENT.md file for guidelines
- Pull request templates
- Refactor the code to get something more agnostic
- Split files into differents modules
- Build units and integrations tests
- Add default config.toml content
- Add custom chains creation, deletion
- Add more tests for api, custom chains

### Fixed

- **Build Warnings Resolution**: Eliminated all compiler and tool warnings
  - Fixed eBPF build failure warnings with intelligent object detection
  - Removed dead code warnings by cleaning up unused constants
  - Resolved useless type limit comparisons for port validation
  - Fixed rustfmt warnings by using stable-compatible configuration
- **API Compatibility**: Resolved breaking changes from dependency upgrades
  - Updated function signatures for new aya-ebpf 0.1 API
  - Fixed field access patterns for network-types 0.0.8
  - Corrected NetshieldRule validation with proper field names

### Security

- **Enhanced eBPF Security Framework**:
  - Added comprehensive security policies and validation
  - Implemented interface filtering and path validation
  - Added privilege control mechanisms for eBPF operations
  - Enhanced bounds checking and input validation
