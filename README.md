# Kinnector Config

Kinnector Config is a high-performance configuration and security policy loading library, providing native Rust APIs and dynamic C++ bindings (`libkinnector_config`). It parses, cryptographically validates, and queries security rules compiled from the Kinnector rules database.

---

## Why this exists

EDR engines evaluate rules on hot telemetry paths where event throughput is high. Parsing text-based configuration formats (such as JSON or YAML) during runtime adds memory allocations and latency, bottlenecking the system.

Kinnector Config solves this by loading pre-compiled, cryptographically signed rules databases (serialized with FlatBuffers). It performs lookups using zero-allocation data structures, ensuring rule checking does not introduce latency into the telemetry loop.

---

## Mental Model and Hot-Reloading

```
[ rules.db File ] ──(Ed25519 Validation)──> [ FlatBuffers Memory Map ] ──(Atomic Swap)──> [ Active Engine Referencer ]
```

At startup, the database is verified using Ed25519 signatures. Once verified, it is mapped directly into memory. To update rules without stopping the daemon or losing telemetry events, the library supports atomic hot-reloading: new databases are parsed and validated in-memory asynchronously, then hot-swapped into the execution thread using lock-free atomic pointers.

---

## Build Requirements

* Rust 1.75+ (Cargo)
* CMake 3.20+ (for C++ dynamic library builds)
* Clang or GCC supporting C++20

---

## Rust Usage

Add the library to your `Cargo.toml` dependency definitions:

```toml
[dependencies]
kinnector-config = { path = "../kinnector-config" }
```

### Example: Checking Exclusions, Vendors, and CLI Rules

```rust
use std::path::Path;
use kinnector_config::{ConfigManager, Category, SignerInfo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize manager and cryptographically validate the rules database
    let public_key_bytes = [0u8; 32]; // Replace with actual Ed25519 public key
    let manager = ConfigManager::load("/etc/kinnector/rules.db", &public_key_bytes)?;

    // Check if a path is excluded from monitoring
    if manager.is_path_excluded(Path::new("/home/user/workspace/build/out.o")) {
        println!("Path is excluded");
    }

    // Check if a process publisher is trusted
    let signer = SignerInfo {
        signer_name: "Google LLC".to_string(),
        team_id: Some("EQHXZ8M8AV".to_string()),
        is_signed: true,
    };
    if manager.is_trusted_vendor(&signer) {
        println!("Signer matches trusted allowlist");
    }

    // Validate if a CLI tool has permissions to access a telemetry category
    if manager.is_trusted_cli(Path::new("/usr/bin/ssh"), Category::SshKeys) {
        println!("ssh binary has explicit credentials access permission");
    }

    // Hot-reload the rules database atomically
    manager.reload()?;

    Ok(())
}
```

---

## C++ Usage

Link your project against `libkinnector_config` and include `kinnector_config.h`.

### Example: Verification inside eBPF Collectors

```cpp
#include <iostream>
#include <memory>
#include "kinnector_config.h"

int main() {
    uint8_t public_key[32] = {0}; // Replace with actual Ed25519 public key
    
    // Load and validate the rules database
    kinnector_config_t* config = nullptr;
    int rc = kinnector_config_load("/etc/kinnector/rules.db", public_key, &config);
    if (rc != 0) {
        std::cerr << "Failed to validate database: " << rc << std::endl;
        return 1;
    }

    // Lookup path exclusion on telemetry hot path
    const char* path = "/tmp/development_build/out.o";
    if (kinnector_config_is_path_excluded(config, path)) {
        std::cout << "Telemetry path excluded" << std::endl;
    }

    // Query trusted vendor information
    signer_info_t signer = {};
    signer.signer_name = "Google LLC";
    signer.team_id = "EQHXZ8M8AV";
    signer.is_signed = true;

    if (kinnector_config_is_trusted_vendor(config, &signer)) {
        std::cout << "Publisher matches trusted vendor signatures" << std::endl;
    }

    // Free configuration resources
    kinnector_config_free(config);
    return 0;
}
```

---

## Database Binary Layout

The compiled rules database payload uses FlatBuffers tables packed in the following order:

1. **Header**: Cryptographic signature, version epoch, and database release metadata.
2. **Metadata**: Targeted platform architectures and configuration flags.
3. **Exclusion List**: Prefix trees (trie structures) for low-overhead path prefix matching.
4. **Signer Allowlist**: Hash-sets of trusted team identifiers and Authenticode names.
5. **Trusted CLI Registry**: Map of binary paths to permitted access categories.
6. **Network CDN Allowlist**: Domain suffix trees for validation of network targets.
