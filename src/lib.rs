pub mod rules_generated;

use std::collections::{HashSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

fn find_config_dir(db_path: &Path) -> PathBuf {
    if let Some(parent) = db_path.parent() {
        let dir = parent.join("configs");
        if dir.exists() {
            return dir;
        }
        let dir = parent.join("../kinnector-protect-community/configs");
        if dir.exists() {
            return dir;
        }
    }
    let dir = Path::new("../kinnector-protect-community/configs");
    if dir.exists() {
        return dir.to_path_buf();
    }
    Path::new(".").to_path_buf()
}

fn load_list_from_json(config_dir: &Path, filename: &str, key: &str) -> Vec<String> {
    let file_path = config_dir.join(filename);
    if file_path.exists() {
        if let Ok(mut file) = File::open(&file_path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if let Some(arr) = v.get(key).and_then(|a| a.as_array()) {
                        let list: Vec<String> = arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
                        if !list.is_empty() {
                            return list;
                        }
                    }
                }
            }
        }
    }
    Vec::new()
}

fn load_map_from_json(config_dir: &Path, filename: &str, key: &str) -> HashMap<String, String> {
    let file_path = config_dir.join(filename);
    if file_path.exists() {
        if let Ok(mut file) = File::open(&file_path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if let Some(obj) = v.get(key).and_then(|a| a.as_object()) {
                        let mut map = HashMap::new();
                        for (k, val) in obj {
                            if let Some(s) = val.as_str() {
                                map.insert(k.clone(), s.to_string());
                            }
                        }
                        if !map.is_empty() {
                            return map;
                        }
                    }
                }
            }
        }
    }
    HashMap::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    BrowserDb       = 0x01,
    Wallet          = 0x04,
    AppData         = 0x08,
    SshKeys         = 0x10,
    UserKeystores   = 0x20,
    AiAgents        = 0x40,
    // Server-specific categories (warden)
    WebProcess      = 0x80,
    SystemUpdate    = 0x100,
    PersistencePath = 0x200,
    ProtectedBinary = 0x400,
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
    installer_binaries:  Vec<String>,
    shell_profile_paths: Vec<String>,
    sensitive_credential_paths: Vec<String>,
    script_interpreters: Vec<String>,
    interactive_shells:  Vec<String>,
    browser_executables: Vec<String>,
    hvnc_monitored_gui_apps: Vec<String>,
    protected_application_directories: HashMap<String, String>,
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
                installer_binaries: Vec::new(),
                shell_profile_paths: Vec::new(),
                sensitive_credential_paths: Vec::new(),
                script_interpreters: Vec::new(),
                interactive_shells: Vec::new(),
                browser_executables: Vec::new(),
                hvnc_monitored_gui_apps: Vec::new(),
                protected_application_directories: HashMap::new(),
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

        let db_path = Path::new(&self.path);
        let config_dir = find_config_dir(db_path);
        let prefix = if cfg!(unix) { "linux" } else { "windows" };

        let mut network_cdns = load_list_from_json(&config_dir, "network_cdns.json", "cdns");
        if let Some(fb_cdns) = rules_db.network_cdns() {
            for entry in fb_cdns {
                if let Some(suffix) = entry.domain_suffix() {
                    let s = suffix.to_string();
                    if !network_cdns.contains(&s) {
                        network_cdns.push(s);
                    }
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

        let mut web_processes = load_list_from_json(&config_dir, &format!("{}_web_processes.json", prefix), "processes");
        let mut persistence_paths = load_list_from_json(&config_dir, &format!("{}_persistence_paths.json", prefix), "paths");
        let mut protected_binaries = load_list_from_json(&config_dir, &format!("{}_protected_binaries.json", prefix), "binaries");
        
        let terminal_rce_patterns = if cfg!(unix) {
            load_list_from_json(&config_dir, "linux_terminal_rce_patterns.json", "patterns")
        } else {
            Vec::new()
        };

        // Extract server-specific dynamic configurations from the FlatBuffers (Category flags)
        if let Some(fb_clis) = rules_db.trusted_clis() {
            for entry in fb_clis {
                if let Some(binary_path) = entry.binary_path() {
                    let flags = entry.category_flags();
                    // WebProcess = 0x80
                    if (flags & 0x80) != 0 {
                        let path = binary_path.to_string();
                        if !web_processes.contains(&path) {
                            web_processes.push(path);
                        }
                    }
                    // ProtectedBinary = 0x400
                    if (flags & 0x400) != 0 {
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
                    // PersistencePath = 0x200
                    if (flags & 0x200) != 0 {
                        let path = file_path.to_string();
                        if !persistence_paths.contains(&path) {
                            persistence_paths.push(path);
                        }
                    }
                }
            }
        }

        let installer_binaries = load_list_from_json(&config_dir, &format!("{}_installer_binaries.json", prefix), "binaries");
        let shell_profile_paths = load_list_from_json(&config_dir, &format!("{}_shell_profile_paths.json", prefix), "paths");
        let sensitive_credential_paths = load_list_from_json(&config_dir, &format!("{}_sensitive_credential_paths.json", prefix), "paths");
        let script_interpreters = load_list_from_json(&config_dir, &format!("{}_script_interpreters.json", prefix), "interpreters");
        let interactive_shells = load_list_from_json(&config_dir, &format!("{}_interactive_shells.json", prefix), "shells");
        let browser_executables = load_list_from_json(&config_dir, &format!("{}_browser_executables.json", prefix), "browsers");
        let hvnc_monitored_gui_apps = load_list_from_json(&config_dir, &format!("{}_hvnc_monitored_gui_apps.json", prefix), "apps");
        let protected_application_directories = load_map_from_json(&config_dir, &format!("{}_protected_application_directories.json", prefix), "directories");

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
            installer_binaries,
            shell_profile_paths,
            sensitive_credential_paths,
            script_interpreters,
            interactive_shells,
            browser_executables,
            hvnc_monitored_gui_apps,
            protected_application_directories,
        };

        Ok(())
    }

    pub fn version(&self) -> u32 {
        self.state.read().unwrap().version
    }

    pub fn epoch_timestamp(&self) -> u64 {
        self.state.read().unwrap().epoch_timestamp
    }

    pub fn is_path_excluded(&self, path: &Path) -> bool {
        let state = self.state.read().unwrap();
        let path_str = path.to_string_lossy().to_lowercase().replace('\\', "/");
        for prefix in &state.exclusions {
            let prefix_normalized = prefix.to_lowercase().replace('\\', "/");
            if path_str.starts_with(&prefix_normalized) {
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
        state.trusted_signers.contains(&(signer.signer_name.clone(), signer.team_id.clone()))
    }

    pub fn is_trusted_cli(&self, path: &Path, category: Category) -> bool {
        let state = self.state.read().unwrap();
        let path_str = path.to_string_lossy().to_lowercase().replace('\\', "/");
        if let Some(flags) = state.trusted_clis.get(&path_str) {
            let cat_flag = category as u32;
            return (flags & cat_flag) != 0;
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
        let path_normalized = path.to_lowercase().replace('\\', "/");
        state.persistence_paths.iter().any(|p| {
            let p_normalized = p.to_lowercase().replace('\\', "/");
            path_normalized.starts_with(&p_normalized)
        })
    }

    pub fn persistence_paths(&self) -> Vec<String> {
        self.state.read().unwrap().persistence_paths.clone()
    }

    pub fn is_protected_binary(&self, path: &str) -> bool {
        let state = self.state.read().unwrap();
        let path_normalized = path.to_lowercase().replace('\\', "/");
        state.protected_binaries.iter().any(|b| {
            let b_normalized = b.to_lowercase().replace('\\', "/");
            path_normalized == b_normalized || path_normalized.ends_with(&format!("/{}", b_normalized))
        })
    }

    pub fn terminal_rce_patterns(&self) -> Vec<String> {
        self.state.read().unwrap().terminal_rce_patterns.clone()
    }

    pub fn installer_binaries(&self) -> Vec<String> {
        self.state.read().unwrap().installer_binaries.clone()
    }

    pub fn shell_profile_paths(&self) -> Vec<String> {
        self.state.read().unwrap().shell_profile_paths.clone()
    }

    pub fn sensitive_credential_paths(&self) -> Vec<String> {
        self.state.read().unwrap().sensitive_credential_paths.clone()
    }

    pub fn script_interpreters(&self) -> Vec<String> {
        self.state.read().unwrap().script_interpreters.clone()
    }

    pub fn interactive_shells(&self) -> Vec<String> {
        self.state.read().unwrap().interactive_shells.clone()
    }

    pub fn browser_executables(&self) -> Vec<String> {
        self.state.read().unwrap().browser_executables.clone()
    }

    pub fn hvnc_monitored_gui_apps(&self) -> Vec<String> {
        self.state.read().unwrap().hvnc_monitored_gui_apps.clone()
    }

    pub fn protected_application_directories(&self) -> HashMap<String, String> {
        self.state.read().unwrap().protected_application_directories.clone()
    }

    pub fn load_defaults() -> Self {
        let config_dir = find_config_dir(Path::new(""));
        let prefix = if cfg!(unix) { "linux" } else { "windows" };

        let network_cdns = load_list_from_json(&config_dir, "network_cdns.json", "cdns");
        let web_processes = load_list_from_json(&config_dir, &format!("{}_web_processes.json", prefix), "processes");
        let persistence_paths = load_list_from_json(&config_dir, &format!("{}_persistence_paths.json", prefix), "paths");
        let protected_binaries = load_list_from_json(&config_dir, &format!("{}_protected_binaries.json", prefix), "binaries");
        
        let terminal_rce_patterns = if cfg!(unix) {
            load_list_from_json(&config_dir, "linux_terminal_rce_patterns.json", "patterns")
        } else {
            Vec::new()
        };

        let installer_binaries = load_list_from_json(&config_dir, &format!("{}_installer_binaries.json", prefix), "binaries");
        let shell_profile_paths = load_list_from_json(&config_dir, &format!("{}_shell_profile_paths.json", prefix), "paths");
        let sensitive_credential_paths = load_list_from_json(&config_dir, &format!("{}_sensitive_credential_paths.json", prefix), "paths");
        let script_interpreters = load_list_from_json(&config_dir, &format!("{}_script_interpreters.json", prefix), "interpreters");
        let interactive_shells = load_list_from_json(&config_dir, &format!("{}_interactive_shells.json", prefix), "shells");
        let browser_executables = load_list_from_json(&config_dir, &format!("{}_browser_executables.json", prefix), "browsers");
        let hvnc_monitored_gui_apps = load_list_from_json(&config_dir, &format!("{}_hvnc_monitored_gui_apps.json", prefix), "apps");
        let protected_application_directories = load_map_from_json(&config_dir, &format!("{}_protected_application_directories.json", prefix), "directories");

        ConfigManager {
            path: String::new(),
            public_key: [0u8; 32],
            state: Arc::new(RwLock::new(ConfigState {
                version: 0,
                epoch_timestamp: 0,
                exclusions: Vec::new(),
                trusted_signers: std::collections::HashSet::new(),
                trusted_clis: std::collections::HashMap::new(),
                network_cdns,
                sensitive_files: std::collections::HashMap::new(),
                web_processes,
                persistence_paths,
                protected_binaries,
                terminal_rce_patterns,
                installer_binaries,
                shell_profile_paths,
                sensitive_credential_paths,
                script_interpreters,
                interactive_shells,
                browser_executables,
                hvnc_monitored_gui_apps,
                protected_application_directories,
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
) -> *mut kinnector_config_t {
    if path.is_null() || public_key.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = CStr::from_ptr(path);
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut key_bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(public_key, key_bytes.as_mut_ptr(), 32);

    match ConfigManager::load(path_str, &key_bytes) {
        Ok(manager) => {
            Box::into_raw(Box::new(kinnector_config_t { manager }))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn kinnector_config_is_path_excluded(
    config: *mut kinnector_config_t,
    path: *const c_char,
) -> bool {
    if config.is_null() || path.is_null() {
        return false;
    }

    let c_str = CStr::from_ptr(path);
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
        0x20 => Category::UserKeystores,
        0x40 => Category::AiAgents,
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

        let db = rules_generated::kinnector_config::RulesDatabase::create(
            &mut builder,
            &rules_generated::kinnector_config::RulesDatabaseArgs {
                version: 42,
                epoch_timestamp: 1625097600,
                exclusions: Some(exclusions_vec),
                trusted_signers: None,
                trusted_clis: None,
                network_cdns: None,
                sensitive_files: None,
                metadata: Some(metadata),
            }
        );

        builder.finish(db, None);
        let payload = builder.finished_data();

        // 2. Cryptographic Sign
        let signing_key = SigningKey::from_bytes(&[
            0u8; 32 // Dummy key for local test
        ]);
        let signature = signing_key.sign(payload);

        // 3. Serialize Header + Payload
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&signature.to_bytes());
        buffer.extend_from_slice(&42u32.to_le_bytes());
        buffer.extend_from_slice(&1625097600u64.to_le_bytes());
        buffer.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buffer.extend_from_slice(payload);

        // Write temp db file
        let db_file_path = "configs_test.db";
        let mut file = File::create(db_file_path)?;
        file.write_all(&buffer)?;

        // 4. Load & Verify
        let pub_key = signing_key.verifying_key().to_bytes();
        let manager = ConfigManager::load(db_file_path, &pub_key)?;

        assert_eq!(manager.version(), 42);
        assert!(manager.is_path_excluded(Path::new("/tmp/exclude/some_subpath")));

        // Cleanup
        std::fs::remove_file(db_file_path)?;
        Ok(())
    }
}
