use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only build eBPF on Linux targets with proper toolchain
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();

    // Check if eBPF is explicitly disabled
    if env::var("FORTEXA_DISABLE_EBPF").is_ok() {
        return;
    }

    if target.contains("linux") && host.contains("linux") {
        // Look for eBPF source in multiple locations (submodule, sibling dir, etc.)
        let possible_ebpf_dirs = [
            "netshield-ebpf",      // As git submodule
            "../netshield-ebpf",   // As sibling directory
            "deps/netshield-ebpf", // As dependency directory
        ];

        let ebpf_dir = possible_ebpf_dirs
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists() && p.join("Cargo.toml").exists());

        let Some(ebpf_dir) = ebpf_dir else {
            // Only show warning if user explicitly wants eBPF support
            if env::var("FORTEXA_REQUIRE_EBPF").is_ok() {
                println!(
                    "cargo:warning=netshield-ebpf source not found, add as git submodule or place in ../netshield-ebpf"
                );
            }
            return;
        };

        println!("cargo:rerun-if-changed={}/src/main.rs", ebpf_dir.display());
        println!("cargo:rerun-if-changed={}/Cargo.toml", ebpf_dir.display());

        // Check if eBPF object already exists before building
        let ebpf_source = ebpf_dir.join("target/bpfel-unknown-none/release/netshield_xdp.o");
        if ebpf_source.exists() {
            // Use existing eBPF object
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let ebpf_dest = out_dir.join("netshield_xdp.o");

            if let Err(e) = std::fs::copy(&ebpf_source, &ebpf_dest) {
                println!("cargo:warning=Failed to copy eBPF object: {e}");
                return;
            }

            println!(
                "cargo:rustc-env=NETSHIELD_EBPF_PATH={}",
                ebpf_dest.display()
            );
            println!("cargo:rustc-cfg=feature=\"ebpf_enabled\"");
            return;
        }

        // Build the eBPF program if object doesn't exist
        let output = Command::new("cargo")
            .args([
                "+nightly",
                "build",
                "--target",
                "bpfel-unknown-none",
                "-Z",
                "build-std=core",
                "--release",
            ])
            .current_dir(&ebpf_dir)
            .output();

        let output = match output {
            Ok(output) => output,
            Err(e) => {
                println!("cargo:warning=Failed to execute eBPF build command: {e}");
                return;
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("cargo:warning=eBPF build failed: {stderr}");
            println!("cargo:warning=eBPF build failed, continuing without eBPF support");
            return;
        }

        // Copy the eBPF object to the output directory
        let ebpf_source = ebpf_dir.join("target/bpfel-unknown-none/release/netshield_xdp.o");
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let ebpf_dest = out_dir.join("netshield_xdp.o");

        if let Err(e) = std::fs::copy(&ebpf_source, &ebpf_dest) {
            println!("cargo:warning=Failed to copy eBPF object: {e}");
            return;
        }

        println!(
            "cargo:rustc-env=NETSHIELD_EBPF_PATH={}",
            ebpf_dest.display()
        );
        println!("cargo:rustc-cfg=feature=\"ebpf_enabled\"");
    } else {
        println!("cargo:warning=Not building eBPF on non-Linux target: {target}");
    }
}
