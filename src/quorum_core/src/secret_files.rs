//! Gap 9 (slice): load secrets from FILES instead of inline config JSON, so a
//! secret manager (Kubernetes/Docker secret mounts, Vault agent, systemd
//! credentials) can inject them and the config file itself holds no secret.
//!
//! Rules (all enforced before the config is deserialized):
//! * only the fields in [`SECRET_FIELDS`] / `api_keys[].key` may use `<field>_file`;
//!   every other `*_file` key (e.g. `ready_file`, `audit_log_file`) is untouched;
//! * giving BOTH the inline value and the `_file` is an error (no silent precedence);
//! * on unix the file must not be readable by group/other (mode & 0o077 == 0);
//! * the file must be non-empty after trimming surrounding whitespace;
//! * errors name the field and path, NEVER the secret content.
//!
//! Not provided: rotation (a changed file is read only at process start), a
//! secret-manager client, or protection of the value once in process memory.

use serde_json::Value;
use std::io::Read;

/// `(file key, inline key it fills)` for every top-level secret field.
pub const SECRET_FIELDS: &[(&str, &str)] = &[
    ("service_auth_key_file", "service_auth_key_b64"),
    ("audit_keypair_file", "audit_keypair_b64"),
    ("key_der_file", "key_der_b64"),
    ("client_key_der_file", "client_key_der_b64"),
    ("tls_key_der_file", "tls_key_der_b64"),
];

/// Upper bound on a secret file (keys here are a few hundred bytes of base64).
const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

fn read_secret(field: &str, path: &str) -> Result<String, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("{field}: cannot open secret file {path}: {e}"))?;
    // Checked on the OPEN handle (fstat), not the path, so the file cannot be
    // swapped between the check and the read.
    let meta = file
        .metadata()
        .map_err(|e| format!("{field}: cannot stat secret file {path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{field}: {path} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{field}: secret file {path} has permissions {mode:o}; it must not be accessible by group or others (chmod 600)"
            ));
        }
    }
    #[cfg(not(unix))]
    {
        return Err(format!(
            "{field}: secret files are only supported on unix (cannot verify permissions of {path})"
        ));
    }
    if meta.len() > MAX_SECRET_FILE_BYTES {
        return Err(format!("{field}: secret file {path} is unreasonably large"));
    }
    let mut text = String::new();
    file.take(MAX_SECRET_FILE_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| format!("{field}: cannot read secret file {path}: {e}"))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("{field}: secret file {path} is empty"));
    }
    Ok(trimmed.to_string())
}

fn resolve_in(
    obj: &mut serde_json::Map<String, Value>,
    pairs: &[(&str, &str)],
) -> Result<(), String> {
    for (file_key, inline_key) in pairs {
        let Some(path_val) = obj.get(*file_key) else {
            continue;
        };
        let Some(path) = path_val.as_str() else {
            return Err(format!("{file_key}: must be a string path"));
        };
        if obj.contains_key(*inline_key) {
            return Err(format!(
                "{inline_key}: set both inline and via {file_key}; give exactly one source"
            ));
        }
        let value = read_secret(file_key, path)?;
        obj.remove(*file_key);
        obj.insert((*inline_key).to_string(), Value::String(value));
    }
    Ok(())
}

/// Resolves every allowed `<field>_file` reference in a parsed config, in place.
pub fn resolve_secret_files(config: &mut Value) -> Result<(), String> {
    let Some(obj) = config.as_object_mut() else {
        return Ok(());
    };
    resolve_in(obj, SECRET_FIELDS)?;
    if let Some(Value::Array(keys)) = obj.get_mut("api_keys") {
        for entry in keys.iter_mut() {
            if let Some(o) = entry.as_object_mut() {
                resolve_in(o, &[("key_file", "key")])?;
            }
        }
    }
    Ok(())
}

/// Parses config JSON text and resolves secret files. Use this instead of
/// `serde_json::from_str` for every service config.
pub fn load_config<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, String> {
    let mut value: Value =
        serde_json::from_str(raw).map_err(|e| format!("invalid config JSON: {e}"))?;
    resolve_secret_files(&mut value)?;
    serde_json::from_value(value).map_err(|e| format!("invalid config: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "secret_files_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn secret(d: &std::path::Path, name: &str, content: &str, mode: u32) -> String {
        let p = d.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn file_value_fills_the_field_and_trailing_newline_is_trimmed() {
        let d = dir();
        let f = secret(&d, "k", "c2VjcmV0\n", 0o600);
        let mut v = json!({"service_auth_key_file": f, "listen_addr": "x"});
        resolve_secret_files(&mut v).unwrap();
        assert_eq!(v["service_auth_key_b64"], "c2VjcmV0");
        assert!(
            v.get("service_auth_key_file").is_none(),
            "the _file key is consumed"
        );
        assert_eq!(v["listen_addr"], "x");
    }

    #[test]
    fn both_inline_and_file_is_refused() {
        let d = dir();
        let f = secret(&d, "k", "abc", 0o600);
        let mut v = json!({"audit_keypair_b64": "inline", "audit_keypair_file": f});
        let e = resolve_secret_files(&mut v).unwrap_err();
        assert!(e.contains("audit_keypair_b64") && e.contains("both"), "{e}");
    }

    #[test]
    fn group_or_world_accessible_secret_files_are_refused() {
        let d = dir();
        for mode in [0o644, 0o640, 0o604, 0o660, 0o777] {
            let f = secret(&d, &format!("k{mode:o}"), "abc", mode);
            let mut v = json!({"key_der_file": f});
            let e = resolve_secret_files(&mut v).unwrap_err();
            assert!(e.contains("permissions"), "mode {mode:o}: {e}");
        }
        let ok = secret(&d, "ok", "abc", 0o400);
        let mut v = json!({"key_der_file": ok});
        resolve_secret_files(&mut v).unwrap();
    }

    #[test]
    fn empty_and_missing_files_are_refused_without_leaking_content() {
        let d = dir();
        let f = secret(&d, "empty", " \n", 0o600);
        let mut v = json!({"tls_key_der_file": f});
        assert!(resolve_secret_files(&mut v).unwrap_err().contains("empty"));
        let mut v = json!({"client_key_der_file": d.join("nope").to_string_lossy()});
        let e = resolve_secret_files(&mut v).unwrap_err();
        assert!(
            e.contains("client_key_der_file") && e.contains("nope"),
            "{e}"
        );
    }

    #[test]
    fn error_messages_never_contain_the_secret() {
        let d = dir();
        let f = secret(&d, "leaky", "TOPSECRETVALUE", 0o644);
        let mut v = json!({"key_der_file": f});
        let e = resolve_secret_files(&mut v).unwrap_err();
        assert!(!e.contains("TOPSECRETVALUE"), "{e}");
    }

    #[test]
    fn api_key_entries_can_use_key_file() {
        let d = dir();
        let f = secret(&d, "api", "api-key-1\n", 0o600);
        let mut v = json!({"api_keys": [
            {"key": "inline-key", "caller_id": "a"},
            {"key_file": f, "caller_id": "b"}
        ]});
        resolve_secret_files(&mut v).unwrap();
        assert_eq!(v["api_keys"][0]["key"], "inline-key");
        assert_eq!(v["api_keys"][1]["key"], "api-key-1");
        assert_eq!(v["api_keys"][1]["caller_id"], "b");
    }

    #[test]
    fn non_secret_file_fields_are_left_alone() {
        let mut v = json!({
            "ready_file": "/tmp/r", "audit_log_file": "/tmp/a", "pubkey_file": "/tmp/p",
            "receipts_file": "/tmp/x", "group_pubkey_file": "/tmp/g"
        });
        let before = v.clone();
        resolve_secret_files(&mut v).unwrap();
        assert_eq!(v, before);
    }
}
