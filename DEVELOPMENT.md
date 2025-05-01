# DEVELOPMENT.md

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
- [Development Workflow](#development-workflow)
- [Running the Project](#running-the-project)
- [Testing](#testing)
- [Code Style](#code-style)
- [Troubleshooting](#troubleshooting)
- [Useful Commands](#useful-commands)
- [Resources](#resources)
- [Contact](#contact)

---

## Introduction

Welcome to the development guide for this Rust project!
This document will help you set up your development environment, run the project, and follow best practices for contributing code.

---

## Prerequisites

Before you begin, ensure you have the following installed:

- [Rust toolchain (rustc, cargo, rustup)](https://www.rust-lang.org/tools/install)
- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/) (optional, for containerized development)
- Any project-specific dependencies listed in the README

---

## Setup Instructions

1. **Clone the repository:**

```bash
git clone https://github.com/Fortexa-FW/fortexa.git
cd fortexa
```

2. **Install Rust toolchain (if not already installed):**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
```

3. **Install project dependencies:**

Cargo will automatically fetch dependencies when you build or run the project.

---

## Development Workflow

- Create a new branch for each feature or bugfix:

```bash
git checkout -b feature/your-feature-name
```

- Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages if required.
- Write clear, concise pull request descriptions and reference related issues.
- Ensure all tests pass before opening a PR.
- Request code review from at least one other contributor.

---

## Running the Project

- **Build the project:**

```bash
cargo build
```

- **Run the project:**

```bash
cargo run
```

- **Build the project for release:**

```bash
cargo build --release
```

- **Run the project release with privileges and debug log-level:**

> [!NOTE]
> The default location if a build is done without `--release` flag is `./target/release/fortexa`.
>
> You can run this command even if you haven't made a release build.
>

```bash
sudo RUST_LOG=debug ./target/release/fortexa
```

---

## Testing

> [!IMPORTANT]
> This project may need some specific right as the iptables and network feature needs privileges to be running.
>
> Some tests need the sudo command, we recommend to always run the tests with `-- --show-output` flag to get skipping message.
>
> If skipping message is displayed use the cargo test command with sudo.
>

- **Run all tests:**

```bash
cargo test -- --include-ignored --show-output
```

- **Run a specific test:**

```bash
cargo test test_name
```

- **Check code coverage (optional):**
    - Install [cargo-tarpaulin](https://github.com/xd009642/tarpaulin):

```bash
cargo install cargo-tarpaulin
```

    - Run coverage:

```bash
cargo tarpaulin
```

---

## Code Style

- **Format your code before committing:**

```bash
cargo fmt
```

- **Check for common mistakes and lints:**

```bash
cargo clippy
```

- **To get further later:** Set up a pre-commit hook to run `cargo fmt` and `cargo clippy`.

---

## Troubleshooting

- **Dependency errors:** Run `cargo clean` and then rebuild.
- **Build errors:** Make sure your Rust toolchain is up to date (`rustup update`).
- **Other issues:** Check [GitHub Issues](../../issues) or open a new one.

---

## Useful Commands

| Command | Description |
| :-- | :-- |
| `cargo build` | Build the project |
| `cargo run` | Run the project |
| `cargo test` | Run tests |
| `cargo fmt` | Format the code |
| `cargo clippy` | Lint the code |
| `cargo doc --open` | Build and open documentation |
| `cargo tarpaulin` | Run code coverage (if installed) |

---

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)
- [Project Documentation](./README.md)
- [Contribution Guidelines](./CONTRIBUTING.md) <!--- FIXME: We will do this later -->
- [Code of Conduct](./CODE_OF_CONDUCT.md) <!--- FIXME: We will do this later -->

---

*Happy hacking with Rust!* 🦀

