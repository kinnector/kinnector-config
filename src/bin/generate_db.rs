use std::fs::File;
use std::io::Write;
use ed25519_dalek::{SigningKey, Signer};
use kinnector_config::rules_generated;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating signed rules database...");

    // 1. Build FlatBuffers Payload
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

    // Path Exclusions
    let excl1_str = builder.create_string("/tmp/exclude");
    let excl1 = rules_generated::kinnector_config::PathExclusion::create(
        &mut builder,
        &rules_generated::kinnector_config::PathExclusionArgs {
            path_prefix: Some(excl1_str),
        }
    );
    let excl2_str = builder.create_string("/home/user/exclude");
    let excl2 = rules_generated::kinnector_config::PathExclusion::create(
        &mut builder,
        &rules_generated::kinnector_config::PathExclusionArgs {
            path_prefix: Some(excl2_str),
        }
    );
    let exclusions_vec = builder.create_vector(&[excl1, excl2]);

    // Trusted Signers (approved vendors)
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

    // Trusted CLIs
    let binary_path = builder.create_string("/usr/bin/ssh");
    let cli1 = rules_generated::kinnector_config::TrustedCLI::create(
        &mut builder,
        &rules_generated::kinnector_config::TrustedCLIArgs {
            binary_path: Some(binary_path),
            category_flags: 0x10, // SshKeys
        }
    );
    let clis_vec = builder.create_vector(&[cli1]);

    // Allowed network CDNs
    let cdn_suffix = builder.create_string("*.google.com");
    let cdn1 = rules_generated::kinnector_config::NetworkCDN::create(
        &mut builder,
        &rules_generated::kinnector_config::NetworkCDNArgs {
            domain_suffix: Some(cdn_suffix),
        }
    );
    let cdns_vec = builder.create_vector(&[cdn1]);

    // Sensitive files to monitor and block
    let file1_str = builder.create_string("/etc/passwd");
    let file1 = rules_generated::kinnector_config::SensitiveFile::create(
        &mut builder,
        &rules_generated::kinnector_config::SensitiveFileArgs {
            file_path: Some(file1_str),
            category_flags: 0x10, // SshKeys (represented by passwd)
        }
    );
    let file2_str = builder.create_string("/etc/shadow");
    let file2 = rules_generated::kinnector_config::SensitiveFile::create(
        &mut builder,
        &rules_generated::kinnector_config::SensitiveFileArgs {
            file_path: Some(file2_str),
            category_flags: 0x10, // SshKeys
        }
    );
    let files_vec = builder.create_vector(&[file1, file2]);

    // Root RulesDatabase
    let root = rules_generated::kinnector_config::RulesDatabase::create(
        &mut builder,
        &rules_generated::kinnector_config::RulesDatabaseArgs {
            version: 1,
            epoch_timestamp: 12345678,
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

    // 2. Cryptographic signature (Ed25519)
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    println!("Public Key Bytes: {:?}", signing_key.verifying_key().to_bytes());
    let signature = signing_key.sign(payload_bytes);
    let signature_bytes = signature.to_bytes();

    // 3. Assemble binary payload
    let mut final_db = Vec::new();
    final_db.extend_from_slice(&signature_bytes); // 64 bytes
    final_db.extend_from_slice(&1u32.to_le_bytes()); // db_version
    final_db.extend_from_slice(&12345678u64.to_le_bytes()); // epoch_timestamp
    final_db.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes()); // payload_len
    final_db.extend_from_slice(payload_bytes);

    // 4. Write to local file
    let local_path = "rules.db";
    let mut file = File::create(local_path)?;
    file.write_all(&final_db)?;

    println!("Rules database generated successfully at: {}", local_path);
    Ok(())
}
