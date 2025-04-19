<p align="center">
  <img src="/assets/img/logo-readme.png">
</p>

# Fortexa
A modern firewall solution built with Rust for superior performance and memory safety. We provide robust network security with minimal overhead, leveraging Rust's speed and reliability to protect your infrastructure against emerging threats.



Kernel-Level Blocking: Handled by FirewallManager via iptables.

Daemon Logging:

Monitors all traffic on the network interface.

Checks packets against current rules.

Prints console messages when blocked traffic is detected (even though the kernel already dropped it).
