use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use kinnector_config::rules_generated;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum CategoryFlags {
    Number(u32),
    Single(String),
    List(Vec<String>),
}

fn resolve_flags(flags_opt: Option<&CategoryFlags>) -> u32 {
    let flags = match flags_opt {
        Some(f) => f,
        None => return 0,
    };
    match flags {
        CategoryFlags::Number(num) => *num,
        CategoryFlags::Single(s) => parse_single_flag(s),
        CategoryFlags::List(list) => {
            let mut val = 0;
            for s in list {
                val |= parse_single_flag(s);
            }
            val
        }
    }
}

fn parse_single_flag(s: &str) -> u32 {
    match s.to_lowercase().as_str() {
        "browserdb" | "browser" | "browser_db" => 0x01,
        "wallet" | "crypto_wallet" | "crypto" => 0x04,
        "appdata" | "app_data" | "app" => 0x08,
        "sshkeys" | "ssh_keys" | "ssh" => 0x10,
        "userkeystores" | "user_keystores" | "keystores" | "keystore" => 0x20,
        "aiagents" | "ai_agents" | "agents" | "agent" => 0x40,
        "webprocess" | "web_process" | "web" => 0x80,
        "systemupdate" | "system_update" | "update" => 0x100,
        "persistencepath" | "persistence_path" | "persistence" => 0x200,
        "protectedbinary" | "protected_binary" | "protected" => 0x400,
        _ => {
            println!("[Policy Compiler] Warning: Unknown flag category '{}'. Defaulting to 0.", s);
            0
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TrustedCliJson {
    path: String,
    category: Option<CategoryFlags>,
    flags: Option<CategoryFlags>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SensitiveFileJson {
    path: String,
    category: Option<CategoryFlags>,
    flags: Option<CategoryFlags>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PolicyJson {
    version: u32,
    exclusions: Option<Vec<String>>,
    trusted_clis: Option<Vec<TrustedCliJson>>,
    sensitive_files: Option<Vec<SensitiveFileJson>>,
    allowed_cdns: Option<Vec<String>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: compile_policy <input_file_or_directory> <output_rules.db> [private_key_file]");
        println!("Example: compile_policy policies/ rules.db");
        std::process::exit(1);
    }

    let input_arg = &args[1];
    let output_path = &args[2];
    let input_path = Path::new(input_arg);

    let mut combined_exclusions = Vec::new();
    let mut combined_clis = Vec::new();
    let mut combined_files = Vec::new();
    let mut combined_cdns = Vec::new();
    let mut max_version = 1;

    // Resolve file paths to load
    let files_to_parse = if input_path.is_dir() {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(input_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                paths.push(path);
            }
        }
        paths
    } else {
        vec![input_path.to_path_buf()]
    };

    if files_to_parse.is_empty() {
        println!("[Policy Compiler] Error: No JSON policy files found in target: {:?}", input_path);
        std::process::exit(1);
    }

    // Ingest all JSON files
    for path in files_to_parse {
        println!("[Policy Compiler] Reading policy file: {:?}", path);
        let mut file = File::open(&path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let policy: PolicyJson = serde_json::from_str(&contents)?;

        if policy.version > max_version {
            max_version = policy.version;
        }
        if let Some(excl) = policy.exclusions {
            combined_exclusions.extend(excl);
        }
        if let Some(clis) = policy.trusted_clis {
            combined_clis.extend(clis);
        }
        if let Some(files) = policy.sensitive_files {
            combined_files.extend(files);
        }
        if let Some(cdns) = policy.allowed_cdns {
            combined_cdns.extend(cdns);
        }
    }

    println!("[Policy Compiler] Combined policy details:");
    println!("  - Total Exclusions: {}", combined_exclusions.len());
    println!("  - Total Sensitive Files: {}", combined_files.len());
    println!("  - Total Trusted CLIs: {}", combined_clis.len());
    println!("  - Total Allowed CDNs: {}", combined_cdns.len());

    // Build FlatBuffers Payload
    let mut builder = flatbuffers::FlatBufferBuilder::new();

    let plat = builder.create_string("linux");
    let base_ver = builder.create_string("1.0.0");
    let metadata = rules_generated::kinnector_config::Metadata::create(
        &mut builder,
        &rules_generated::kinnector_config::MetadataArgs {
            platform: Some(plat),
            baseline_version: Some(base_ver),
        }
    );

    // Build Exclusions vector
    let mut excl_offsets = Vec::new();
    for excl in &combined_exclusions {
        let excl_str = builder.create_string(excl);
        let excl_obj = rules_generated::kinnector_config::PathExclusion::create(
            &mut builder,
            &rules_generated::kinnector_config::PathExclusionArgs {
                path_prefix: Some(excl_str),
            }
        );
        excl_offsets.push(excl_obj);
    }
    let exclusions_vec = builder.create_vector(&excl_offsets);

    // Build Trusted Signers (we hardcode mock signer for compatibility)
    let signer_name = builder.create_string("Google LLC");
    let team_id = builder.create_string("EQHXZ8M8AV");
    let signer1 = rules_generated::kinnector_config::TrustedSigner::create(
        &mut builder,
        &rules_generated::kinnector_config::TrustedSignerArgs {
            signer_name: Some(signer_name),
            team_id: Some(team_id),
        }
    );
    let signers_vec = builder.create_vector(&[signer1]);

    // Build Trusted CLIs vector
    let mut cli_offsets = Vec::new();
    for cli in &combined_clis {
        let cli_path = builder.create_string(&cli.path);
        let flags = resolve_flags(cli.category.as_ref().or(cli.flags.as_ref()));
        let cli_obj = rules_generated::kinnector_config::TrustedCLI::create(
            &mut builder,
            &rules_generated::kinnector_config::TrustedCLIArgs {
                binary_path: Some(cli_path),
                category_flags: flags,
            }
        );
        cli_offsets.push(cli_obj);
    }
    let clis_vec = builder.create_vector(&cli_offsets);

    // Build Allowed CDNs vector
    let mut cdn_offsets = Vec::new();
    for cdn in &combined_cdns {
        let cdn_str = builder.create_string(cdn);
        let cdn_obj = rules_generated::kinnector_config::NetworkCDN::create(
            &mut builder,
            &rules_generated::kinnector_config::NetworkCDNArgs {
                domain_suffix: Some(cdn_str),
            }
        );
        cdn_offsets.push(cdn_obj);
    }
    let cdns_vec = builder.create_vector(&cdn_offsets);

    // Build Sensitive Files vector
    let mut file_offsets = Vec::new();
    for sf in &combined_files {
        let file_path = builder.create_string(&sf.path);
        let flags = resolve_flags(sf.category.as_ref().or(sf.flags.as_ref()));
        let file_obj = rules_generated::kinnector_config::SensitiveFile::create(
            &mut builder,
            &rules_generated::kinnector_config::SensitiveFileArgs {
                file_path: Some(file_path),
                category_flags: flags,
            }
        );
        file_offsets.push(file_obj);
    }
    let files_vec = builder.create_vector(&file_offsets);

    // Build Root RulesDatabase
    let root = rules_generated::kinnector_config::RulesDatabase::create(
        &mut builder,
        &rules_generated::kinnector_config::RulesDatabaseArgs {
            version: max_version,
            epoch_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            metadata: Some(metadata),
            exclusions: Some(exclusions_vec),
            trusted_signers: Some(signers_vec),
            trusted_clis: Some(clis_vec),
            network_cdns: Some(cdns_vec),
            sensitive_files: Some(files_vec),
        }
    );
    builder.finish(root, None);
    let payload_bytes = builder.finished_data();

    // 3. Resolve Signing Key
    let signing_key = if args.len() >= 4 {
        let key_path = &args[3];
        println!("[Policy Compiler] Reading private signing key from: {}", key_path);
        let mut key_file = File::open(key_path)?;
        let mut key_bytes = [0u8; 32];
        key_file.read_exact(&mut key_bytes)?;
        SigningKey::from_bytes(&key_bytes)
    } else {
        println!("[Policy Compiler] Using default development private key...");
        SigningKey::from_bytes(&[42u8; 32])
    };

    println!("[Policy Compiler] Verifying Public Key Bytes: {:?}", signing_key.verifying_key().to_bytes());

    // 4. Compute Cryptographic Signature
    let signature = signing_key.sign(payload_bytes);
    let signature_bytes = signature.to_bytes();

    // 5. Pack Custom 80-Byte Header + Payload
    let mut final_db = Vec::new();
    final_db.extend_from_slice(&signature_bytes); // 64 bytes
    final_db.extend_from_slice(&max_version.to_le_bytes()); // db_version (4 bytes)
    
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    final_db.extend_from_slice(&now_epoch.to_le_bytes()); // epoch_timestamp (8 bytes)
    final_db.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes()); // payload_len (4 bytes)
    final_db.extend_from_slice(payload_bytes);

    // 6. Write Signed Binary Rules Database
    let mut out_file = File::create(output_path)?;
    out_file.write_all(&final_db)?;

    println!("[Policy Compiler] Success! Rules database generated at: {}", output_path);
    Ok(())
}
