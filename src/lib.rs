pub mod rules_generated;

use std::collections::{HashSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    BrowserDb = 0x01,
    Wallet = 0x04,
    AppData = 0x08,
    SshKeys = 0x10,
    // Server-specific categories (warden)
    WebProcess      = 0x20,
    SystemUpdate    = 0x40,
    PersistencePath = 0x80,
    ProtectedBinary = 0x100,
}

#[derive(Debug, Clone)]
pub struct SignerInfo {
    pub signer_name: String,
    pub team_id: Option<String>,
    pub is_signed: bool,
}

struct ConfigState {
    version: u32,
    epoch_timestamp: u64,
    exclusions: Vec<String>,
    trusted_signers: HashSet<(String, Option<String>)>,
    trusted_clis: HashMap<String, u32>,
    network_cdns: Vec<String>,
    sensitive_files: HashMap<String, u32>,
    web_processes:       Vec<String>,
    persistence_paths:   Vec<String>,
    protected_binaries:  Vec<String>,
    terminal_rce_patterns: Vec<String>,
}

pub struct ConfigManager {
    path: String,
    public_key: [u8; 32],
    state: Arc<RwLock<ConfigState>>,
}

impl ConfigManager {
    pub fn load<P: AsRef<Path>>(path: P, public_key_bytes: &[u8; 32]) -> Result<Self, Box<dyn std::error::Error>> {
        let path_str = path.as_ref().to_string_lossy().into_owned();
        let manager = ConfigManager {
            path: path_str,
            public_key: *public_key_bytes,
            state: Arc::new(RwLock::new(ConfigState {
                version: 0,
                epoch_timestamp: 0,
                exclusions: Vec::new(),
                trusted_signers: HashSet::new(),
                trusted_clis: HashMap::new(),
                network_cdns: Vec::new(),
                sensitive_files: HashMap::new(),
                web_processes: Vec::new(),
                persistence_paths: Vec::new(),
                protected_binaries: Vec::new(),
                terminal_rce_patterns: Vec::new(),
            })),
        };
        manager.reload()?;
        Ok(manager)
    }

    pub fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::open(&self.path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        self.reload_from_bytes(&buffer)
    }

    pub fn reload_from_bytes(&self, buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if buffer.len() < 80 {
            return Err("Config file too small".into());
        }

        // 1. Parse Header
        let signature_bytes: [u8; 64] = buffer[0..64].try_into()?;
        let db_version = u32::from_le_bytes(buffer[64..68].try_into()?);
        let epoch_timestamp = u64::from_le_bytes(buffer[68..76].try_into()?);
        let payload_len = u32::from_le_bytes(buffer[76..80].try_into()?);

        if buffer.len() < 80 + payload_len as usize {
            return Err("Buffer truncated, payload_len exceeds file size".into());
        }

        let payload_bytes = &buffer[80..(80 + payload_len as usize)];

        // 2. Verify Cryptographic Signature (Ed25519)
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key.verify(payload_bytes, &signature)?;

        // 3. Deserialize FlatBuffers Payload
        let rules_db = rules_generated::kinnector_config::root_as_rules_database(payload_bytes)?;

        // 4. Construct optimized memory tables
        let mut exclusions = Vec::new();
        if let Some(fb_exclusions) = rules_db.exclusions() {
            for entry in fb_exclusions {
                if let Some(prefix) = entry.path_prefix() {
                    exclusions.push(prefix.to_string());
                }
            }
        }

        let mut trusted_signers = HashSet::new();
        if let Some(fb_signers) = rules_db.trusted_signers() {
            for entry in fb_signers {
                if let Some(name) = entry.signer_name() {
                    let team_id = entry.team_id().map(|s| s.to_string());
                    trusted_signers.insert((name.to_string(), team_id));
                }
            }
        }

        let mut trusted_clis = HashMap::new();
        if let Some(fb_clis) = rules_db.trusted_clis() {
            for entry in fb_clis {
                if let Some(binary_path) = entry.binary_path() {
                    trusted_clis.insert(binary_path.to_string(), entry.category_flags());
                }
            }
        }

        let mut network_cdns = Vec::new();
        if let Some(fb_cdns) = rules_db.network_cdns() {
            for entry in fb_cdns {
                if let Some(suffix) = entry.domain_suffix() {
                    network_cdns.push(suffix.to_string());
                }
            }
        }

        let mut sensitive_files = HashMap::new();
        if let Some(fb_files) = rules_db.sensitive_files() {
            for entry in fb_files {
                if let Some(file_path) = entry.file_path() {
                    sensitive_files.insert(file_path.to_string(), entry.category_flags());
                }
            }
        }

        // Server-security defaults — these are merged with FlatBuffers rules (no hardcoding)
        let mut web_processes = vec![
            "nginx".to_string(), "apache2".to_string(), "httpd".to_string(),
            "caddy".to_string(), "php-fpm".to_string(), "node".to_string(),
            "python3".to_string(), "python".to_string(), "ruby".to_string(),
            "java".to_string(), "gunicorn".to_string(), "uvicorn".to_string(),
            "uwsgi".to_string(), "lighttpd".to_string(),
        ];

        let mut persistence_paths = vec![
            "/etc/cron.d".to_string(), "/etc/cron.daily".to_string(),
            "/etc/cron.hourly".to_string(), "/etc/cron.weekly".to_string(),
            "/etc/cron.monthly".to_string(), "/var/spool/cron".to_string(),
            "/etc/systemd/system".to_string(), "/usr/lib/systemd/system".to_string(),
            "/etc/profile.d".to_string(), "/etc/rc.d".to_string(),
            "/etc/init.d".to_string(), "/etc/rc.local".to_string(),
            "/root/.bashrc".to_string(), "/root/.bash_profile".to_string(),
            "/etc/bash.bashrc".to_string(),
        ];

        let mut protected_binaries = vec![
            "nginx".to_string(), "apache2".to_string(), "httpd".to_string(),
            "php-fpm".to_string(), "sshd".to_string(), "cron".to_string(),
            "systemd".to_string(), "init".to_string(),
        ];

        let terminal_rce_patterns = vec![
            "wget ".to_string(), "curl ".to_string(), "nc ".to_string(),
            "netcat".to_string(), "ncat".to_string(), "bash -i".to_string(),
            "/dev/tcp/".to_string(), "/dev/udp/".to_string(),
            "python -c".to_string(), "python3 -c".to_string(),
            "perl -e".to_string(), "ruby -e".to_string(),
            "php -r".to_string(), "base64 -d".to_string(),
            "chmod +x".to_string(), "chmod 777".to_string(),
            "mkfifo".to_string(), "LD_PRELOAD".to_string(),
        ];

        // 4. Extract server-specific dynamic configurations from the FlatBuffers (Category flags)
        if let Some(fb_clis) = rules_db.trusted_clis() {
            for entry in fb_clis {
                if let Some(binary_path) = entry.binary_path() {
                    let flags = entry.category_flags();
                    // WebProcess = 0x20
                    if (flags & 0x20) != 0 {
                        let path = binary_path.to_string();
                        if !web_processes.contains(&path) {
                            web_processes.push(path);
                        }
                    }
                    // ProtectedBinary = 0x100
                    if (flags & 0x100) != 0 {
                        let path = binary_path.to_string();
                        if !protected_binaries.contains(&path) {
                            protected_binaries.push(path);
                        }
                    }
                }
            }
        }

        if let Some(fb_files) = rules_db.sensitive_files() {
            for entry in fb_files {
                if let Some(file_path) = entry.file_path() {
                    let flags = entry.category_flags();
                    // PersistencePath = 0x80
                    if (flags & 0x80) != 0 {
                        let path = file_path.to_string();
                        if !persistence_paths.contains(&path) {
                            persistence_paths.push(path);
                        }
                    }
                }
            }
        }

        // 5. Atomic swap
        let mut state = self.state.write().unwrap();
        *state = ConfigState {
            version: db_version,
            epoch_timestamp,
            exclusions,
            trusted_signers,
            trusted_clis,
            network_cdns,
            sensitive_files,
            web_processes,
            persistence_paths,
            protected_binaries,
            terminal_rce_patterns,
        };

        Ok(())
    }

    pub fn version(&self) -> u32 {
        self.state.read().unwrap().version
    }

    pub fn epoch_timestamp(&self) -> u64 {
        self.state.read().unwrap().epoch_timestamp
    }

    pub fn is_path_excluded<P: AsRef<Path>>(&self, path: P) -> bool {
        let path_str = path.as_ref().to_string_lossy();
        let state = self.state.read().unwrap();
        for prefix in &state.exclusions {
            if path_str.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    pub fn is_trusted_vendor(&self, signer: &SignerInfo) -> bool {
        if !signer.is_signed {
            return false;
        }
        let state = self.state.read().unwrap();
        if state.trusted_signers.contains(&(signer.signer_name.clone(), signer.team_id.clone())) {
            return true;
        }
        if state.trusted_signers.contains(&(signer.signer_name.clone(), None)) {
            return true;
        }
        false
    }

    pub fn is_trusted_cli<P: AsRef<Path>>(&self, binary_path: P, category: Category) -> bool {
        let path_str = binary_path.as_ref().to_string_lossy();
        let state = self.state.read().unwrap();
        if let Some(&flags) = state.trusted_clis.get(path_str.as_ref()) {
            return (flags & (category as u32)) != 0;
        }
        false
    }

    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        let state = self.state.read().unwrap();
        for suffix in &state.network_cdns {
            if suffix.starts_with("*.") {
                let base = &suffix[2..];
                if domain == base || domain.ends_with(&format!(".{}", base)) {
                    return true;
                }
            } else if domain == suffix {
                return true;
            }
        }
        false
    }

    pub fn sensitive_files(&self) -> HashMap<String, u32> {
        let state = self.state.read().unwrap();
        state.sensitive_files.clone()
    }

    pub fn is_web_process(&self, exe: &str) -> bool {
        let state = self.state.read().unwrap();
        let exe_lower = exe.to_lowercase();
        state.web_processes.iter().any(|w| exe_lower.contains(w.as_str()))
    }

    pub fn web_processes(&self) -> Vec<String> {
        self.state.read().unwrap().web_processes.clone()
    }

    pub fn is_persistence_path(&self, path: &str) -> bool {
        let state = self.state.read().unwrap();
        state.persistence_paths.iter().any(|p| path.starts_with(p.as_str()))
    }

    pub fn is_protected_binary(&self, path: &str) -> bool {
        let state = self.state.read().unwrap();
        let path_lower = path.to_lowercase();
        state.protected_binaries.iter().any(|b| {
            path_lower == b.as_str() || path_lower.ends_with(&format!("/{}", b))
        })
    }

    pub fn terminal_rce_patterns(&self) -> Vec<String> {
        self.state.read().unwrap().terminal_rce_patterns.clone()
    }

    pub fn load_defaults() -> Self {
        ConfigManager {
            path: String::new(),
            public_key: [0u8; 32],
            state: Arc::new(RwLock::new(ConfigState {
                version: 0,
                epoch_timestamp: 0,
                exclusions: Vec::new(),
                trusted_signers: std::collections::HashSet::new(),
                trusted_clis: std::collections::HashMap::new(),
                network_cdns: Vec::new(),
                sensitive_files: std::collections::HashMap::new(),
                web_processes: vec![
                    "nginx".to_string(), "apache2".to_string(), "httpd".to_string(),
                    "caddy".to_string(), "php-fpm".to_string(), "node".to_string(),
                    "python3".to_string(), "python".to_string(), "ruby".to_string(),
                    "java".to_string(), "gunicorn".to_string(), "uvicorn".to_string(),
                    "uwsgi".to_string(), "lighttpd".to_string(),
                ],
                persistence_paths: vec![
                    "/etc/cron.d".to_string(), "/etc/cron.daily".to_string(),
                    "/etc/cron.hourly".to_string(), "/etc/cron.weekly".to_string(),
                    "/var/spool/cron".to_string(), "/etc/systemd/system".to_string(),
                    "/usr/lib/systemd/system".to_string(), "/etc/profile.d".to_string(),
                    "/etc/init.d".to_string(), "/root/.bashrc".to_string(),
                ],
                protected_binaries: vec![
                    "nginx".to_string(), "apache2".to_string(), "httpd".to_string(),
                    "php-fpm".to_string(), "sshd".to_string(), "cron".to_string(),
                ],
                terminal_rce_patterns: vec![
                    "wget ".to_string(), "curl ".to_string(), "nc ".to_string(),
                    "netcat".to_string(), "bash -i".to_string(),
                    "/dev/tcp/".to_string(), "python -c".to_string(),
                    "python3 -c".to_string(), "perl -e".to_string(),
                    "base64 -d".to_string(), "chmod +x".to_string(),
                    "mkfifo".to_string(), "LD_PRELOAD".to_string(),
                ],
            })),
        }
    }
}

// =========================================================================
// FFI C-Bindings implementation
// =========================================================================

use std::ffi::CStr;
use libc::{c_char, c_int};

#[allow(non_camel_case_types)]
pub struct kinnector_config_t {
    manager: ConfigManager,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct signer_info_t {
    pub signer_name: *const c_char,
    pub team_id: *const c_char,
    pub is_signed: bool,
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_load(
    path: *const c_char,
    public_key: *const u8,
    out_config: *mut *mut kinnector_config_t,
) -> c_int {
    if path.is_null() || public_key.is_null() || out_config.is_null() {
        return -1;
    }

    let c_path = CStr::from_ptr(path);
    let path_str = match c_path.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let mut key_bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(public_key, key_bytes.as_mut_ptr(), 32);

    match ConfigManager::load(path_str, &key_bytes) {
        Ok(mgr) => {
            let boxed = Box::new(kinnector_config_t { manager: mgr });
            *out_config = Box::into_raw(boxed);
            0
        }
        Err(_) => -3,
    }
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_reload(config: *mut kinnector_config_t) -> c_int {
    if config.is_null() {
        return -1;
    }
    match (*config).manager.reload() {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_is_path_excluded(
    config: *mut kinnector_config_t,
    file_path: *const c_char,
) -> bool {
    if config.is_null() || file_path.is_null() {
        return false;
    }
    let c_str = CStr::from_ptr(file_path);
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    (*config).manager.is_path_excluded(Path::new(path_str))
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_is_trusted_vendor(
    config: *mut kinnector_config_t,
    signer: *const signer_info_t,
) -> bool {
    if config.is_null() || signer.is_null() {
        return false;
    }

    let raw_signer = &*signer;
    if raw_signer.signer_name.is_null() {
        return false;
    }

    let name = match CStr::from_ptr(raw_signer.signer_name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return false,
    };

    let team_id = if raw_signer.team_id.is_null() {
        None
    } else {
        match CStr::from_ptr(raw_signer.team_id).to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => None,
        }
    };

    let r_signer = SignerInfo {
        signer_name: name,
        team_id,
        is_signed: raw_signer.is_signed,
    };

    (*config).manager.is_trusted_vendor(&r_signer)
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_is_trusted_cli(
    config: *mut kinnector_config_t,
    binary_path: *const c_char,
    category_flag: u32,
) -> bool {
    if config.is_null() || binary_path.is_null() {
        return false;
    }

    let c_str = CStr::from_ptr(binary_path);
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let category = match category_flag {
        0x01 => Category::BrowserDb,
        0x04 => Category::Wallet,
        0x08 => Category::AppData,
        0x10 => Category::SshKeys,
        _ => return false,
    };

    (*config).manager.is_trusted_cli(Path::new(path_str), category)
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_is_domain_allowed(
    config: *mut kinnector_config_t,
    domain: *const c_char,
) -> bool {
    if config.is_null() || domain.is_null() {
        return false;
    }
    let c_str = CStr::from_ptr(domain);
    let domain_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    (*config).manager.is_domain_allowed(domain_str)
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_free(config: *mut kinnector_config_t) {
    if !config.is_null() {
        let _ = Box::from_raw(config);
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use ed25519_dalek::{SigningKey, Signer};

    #[test]
    fn test_rules_loading_and_matching() -> Result<(), Box<dyn std::error::Error>> {
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

        let excl_str1 = builder.create_string("/tmp/exclude");
        let excl1 = rules_generated::kinnector_config::PathExclusion::create(
            &mut builder,
            &rules_generated::kinnector_config::PathExclusionArgs {
                path_prefix: Some(excl_str1),
            }
        );
        let exclusions_vec = builder.create_vector(&[excl1]);

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

        let binary_path = builder.create_string("/usr/bin/ssh");
        let cli1 = rules_generated::kinnector_config::TrustedCLI::create(
            &mut builder,
            &rules_generated::kinnector_config::TrustedCLIArgs {
                binary_path: Some(binary_path),
                category_flags: 0x10, // Category::SshKeys
            }
        );
        let clis_vec = builder.create_vector(&[cli1]);

        let cdn_suffix = builder.create_string("*.google.com");
        let cdn1 = rules_generated::kinnector_config::NetworkCDN::create(
            &mut builder,
            &rules_generated::kinnector_config::NetworkCDNArgs {
                domain_suffix: Some(cdn_suffix),
            }
        );
        let cdns_vec = builder.create_vector(&[cdn1]);

        let file_path = builder.create_string("/etc/passwd");
        let file1 = rules_generated::kinnector_config::SensitiveFile::create(
            &mut builder,
            &rules_generated::kinnector_config::SensitiveFileArgs {
                file_path: Some(file_path),
                category_flags: 0x10, // Category::SshKeys
            }
        );
        let files_vec = builder.create_vector(&[file1]);

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

        // 2. Generate cryptographically signed Header
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(payload_bytes);
        let signature_bytes = signature.to_bytes();

        let mut final_db = Vec::new();
        final_db.extend_from_slice(&signature_bytes); // 64 bytes
        final_db.extend_from_slice(&1u32.to_le_bytes()); // db_version (4 bytes)
        final_db.extend_from_slice(&12345678u64.to_le_bytes()); // epoch_timestamp (8 bytes)
        final_db.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes()); // payload_len (4 bytes)
        final_db.extend_from_slice(payload_bytes);

        // 3. Write payload to workspace test file
        let db_path = "test_rules.db";
        let mut file = File::create(db_path)?;
        file.write_all(&final_db)?;

        // 4. Load database and verify queries
        let manager = ConfigManager::load(db_path, &public_key_bytes)?;

        // Assert Path Exclusion
        assert!(manager.is_path_excluded("/tmp/exclude/some_subpath"));
        assert!(!manager.is_path_excluded("/usr/bin/some_other_path"));

        // Assert Trusted Signer
        let google_signer = SignerInfo {
            signer_name: "Google LLC".to_string(),
            team_id: Some("EQHXZ8M8AV".to_string()),
            is_signed: true,
        };
        let unknown_signer = SignerInfo {
            signer_name: "Unknown Vendor".to_string(),
            team_id: None,
            is_signed: true,
        };
        assert!(manager.is_trusted_vendor(&google_signer));
        assert!(!manager.is_trusted_vendor(&unknown_signer));

        // Assert Trusted CLI
        assert!(manager.is_trusted_cli("/usr/bin/ssh", Category::SshKeys));
        assert!(!manager.is_trusted_cli("/usr/bin/ssh", Category::BrowserDb));

        // Assert Domain Suffix matching
        assert!(manager.is_domain_allowed("sub.google.com"));
        assert!(manager.is_domain_allowed("google.com"));
        assert!(!manager.is_domain_allowed("yahoo.com"));

        // Assert Sensitive Files mapping
        let files = manager.sensitive_files();
        assert_eq!(files.get("/etc/passwd"), Some(&0x10));

        // 5. Cleanup
        std::fs::remove_file(db_path)?;

        Ok(())
    }
}
