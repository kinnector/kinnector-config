# kinnector-config

A high-performance Rust and C++ configuration and rule loading library for the **kinnector** EDR. It parses, cryptographically validates, and queries rules compiled from the `kinnector-protect-community` repository.

## Features

- **Multi-Language Interfaces**: Native Rust API and dynamic C++ bindings (`libkinnector_config`).
- **Signature Verification**: Verifies signed rule databases using Ed25519 before loading.
- **Zero-Allocation Hot Path**: Optimized lookups for path exclusions, trusted signers, and CLI rules.
- **Atomic Hot-Reloading**: Reloads rules in-memory using atomic pointers without blocking hot telemetry paths.

---

## Build Requirements

- Rust 1.75+ (Cargo)
- CMake 3.20+ (for C++ builds)
- Clang / GCC (supporting C++20)

---

## Rust Usage

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
kinnector-config = { path = "../kinnector-config" }
```

### Example: Checking Exclusions and Trusted Signers

```rust
use std::path::Path;
use kinnector_config::{ConfigManager, Category, SignerInfo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the config manager and load a signed rule database
    let public_key_bytes = [0u8; 32]; // Replace with actual public key
    let manager = ConfigManager::load("/etc/kinnector/rules.db", &public_key_bytes)?;

    // Hot-path check if path is excluded
    if manager.is_path_excluded(Path::new("/home/user/workspace/test.rs")) {
        println!("Path is excluded");
    }

    // Check if a process signature is an approved vendor
    let signer = SignerInfo {
        signer_name: "Google LLC".to_string(),
        team_id: Some("EQHXZ8M8AV".to_string()),
        is_signed: true,
    };
    
    if manager.is_trusted_vendor(&signer) {
        println!("Process is trusted vendor");
    }

    // Check if CLI tool is allowed to access specific category
    if manager.is_trusted_cli(Path::new("/usr/bin/ssh"), Category::SshKeys) {
        println!("ssh is allowed to read SSH keys");
    }

    Ok(())
}
```

---

## C++ Usage

Link against `libkinnector_config` and include `kinnector_config.h`.

### Example: Integration in C++ eBPF/Telemetry Collectors

```cpp
#include <iostream>
#include <memory>
#include "kinnector_config.h"

int main() {
    uint8_t public_key[32] = {0}; // Replace with actual public key
    
    // Initialize configuration instance
    kinnector_config_t* config = nullptr;
    int rc = kinnector_config_load("/etc/kinnector/rules.db", public_key, &config);
    if (rc != 0) {
        std::cerr << "Failed to load rules database: " << rc << std::endl;
        return 1;
    }

    // Hot-path exclusion lookup
    const char* file_path = "/tmp/developer_workspace/build.o";
    if (kinnector_config_is_path_excluded(config, file_path)) {
        std::cout << "Path excluded" << std::endl;
    }

    // Query trusted signer
    signer_info_t signer = {};
    signer.signer_name = "Google LLC";
    signer.team_id = "EQHXZ8M8AV";
    signer.is_signed = true;

    if (kinnector_config_is_trusted_vendor(config, &signer)) {
        std::cout << "Trusted vendor" << std::endl;
    }

    // Cleanup
    kinnector_config_free(config);
    return 0;
}
```

---

## Architecture & Database Schema

The library parses a binary payload containing serialized FlatBuffers tables:

1. **Header**: Cryptographic signature, database version, and epoch timestamp.
2. **Metadata Table**: Target platform indicators and baseline version.
3. **Exclusion List**: Prefix trees (trie) for path prefix matching.
4. **Signer Allowlist**: Hash-sets of trusted publishers (Team IDs and Windows Authenticode Names).
5. **Trusted CLI Registry**: Mappings of utility binaries to allowed `CategoryFlags`.
6. **Network CDN Allowlist**: Wildcard domain suffix trees.

---

## Configuration Updates

To trigger an in-memory hot-swap of the active configuration:

```rust
// Reloads and validates the database at runtime.
// Swaps the active pointer atomically.
manager.reload()?;
```
