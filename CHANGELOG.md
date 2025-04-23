# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
