//! ChatGPT/Codex auth token persistence — ported from themion's
//! `crates/themion-cli/src/auth_store.rs` with the config-dir convention
//! adapted to thClaws's XDG-on-all-platforms pattern.
//!
//! Storage:
//! - per-profile: `~/.config/thclaws/auth/<profile>.json` (mode 0600 on Unix)
//! - legacy single-file: `~/.config/thclaws/auth.json` (auto-migrated)
//!
//! See [`crate::oauth`] for the MCP server OAuth tokens — that's a separate
//! file (`oauth_tokens.json`) for a different concern; the two never share
//! state.

use crate::codex_auth::CodexAuth;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

const LEGACY_AUTH_FILE: &str = "auth.json";
const PROFILE_AUTH_DIR: &str = "auth";

/// `~/.config/thclaws/`. Uses [`crate::util::home_dir`] for cross-platform
/// `HOME` resolution. Matches `secrets.rs` and `oauth.rs` conventions —
/// thClaws does NOT use macOS `Library/Application Support/` even on macOS.
fn thclaws_config_dir() -> Option<PathBuf> {
    crate::util::home_dir().map(|h| h.join(".config").join("thclaws"))
}

fn sanitize_profile_name(profile: &str) -> String {
    let mut out = String::with_capacity(profile.len());
    for ch in profile.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "profile".to_string()
    } else {
        out
    }
}

fn profile_auth_path(profile: &str) -> Option<PathBuf> {
    thclaws_config_dir().map(|d| {
        d.join(PROFILE_AUTH_DIR)
            .join(format!("{}.json", sanitize_profile_name(profile)))
    })
}

pub fn legacy_auth_path() -> Option<PathBuf> {
    thclaws_config_dir().map(|d| d.join(LEGACY_AUTH_FILE))
}

fn load_auth_file(path: &Path) -> Result<Option<CodexAuth>> {
    if !path.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&s)?))
}

fn save_auth_file(path: &Path, auth: &CodexAuth) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Config("cannot determine auth directory".into()))?;
    std::fs::create_dir_all(parent)?;
    let json = serde_json::to_string_pretty(auth)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load the saved CodexAuth for a named profile, or `Ok(None)` if no file.
pub fn load_for_profile(profile: &str) -> Result<Option<CodexAuth>> {
    let path = match profile_auth_path(profile) {
        Some(path) => path,
        None => return Ok(None),
    };
    load_auth_file(&path)
}

/// Persist CodexAuth atomically (write tmp → rename) with 0600 perms on Unix.
pub fn save_for_profile(profile: &str, auth: &CodexAuth) -> Result<()> {
    let path = profile_auth_path(profile)
        .ok_or_else(|| Error::Config("cannot determine config dir".into()))?;
    save_auth_file(&path, auth)
}

/// Load legacy `~/.config/thclaws/auth.json` (single-file layout from before
/// the per-profile split). Returns `Ok(None)` if absent.
pub fn load_legacy() -> Result<Option<CodexAuth>> {
    let path = match legacy_auth_path() {
        Some(path) => path,
        None => return Ok(None),
    };
    load_auth_file(&path)
}

/// If a legacy `auth.json` exists and the per-profile file does NOT, copy
/// the legacy value to the per-profile path. Returns the (possibly
/// migrated) auth value.
pub fn migrate_legacy_to_profile(profile: &str) -> Result<Option<CodexAuth>> {
    let Some(auth) = load_legacy()? else {
        return Ok(None);
    };
    if load_for_profile(profile)?.is_none() {
        save_for_profile(profile, &auth)?;
    }
    Ok(Some(auth))
}

/// Import auth from the official Codex CLI's `~/.codex/auth.json` file
/// (different on-disk format from ours), convert to [`CodexAuth`], and save
/// to the named profile. Returns `Ok(None)` if `~/.codex/auth.json` doesn't
/// exist; errors propagate if the file is malformed.
///
/// Codex CLI's shape (relevant fields only):
/// ```json
/// { "tokens": { "access_token": "...", "refresh_token": "...",
///               "account_id": "...", "id_token": "..." },
///   "auth_mode": "...", "last_refresh": "..." }
/// ```
///
/// We extract:
/// - `tokens.access_token` → `access_token`
/// - `tokens.refresh_token` → `refresh_token`
/// - `tokens.account_id` → `account_id`
/// - `expires_at` derived from the JWT `exp` claim of `tokens.access_token`,
///   falling back to `now + 28 days` if extraction fails (refresh tokens
///   are long-lived; access rotates anyway).
pub fn import_from_codex_cli(profile: &str) -> Result<Option<CodexAuth>> {
    let codex_auth_path = crate::util::home_dir().map(|h| h.join(".codex/auth.json"));
    let Some(path) = codex_auth_path else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(&path)?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let tokens = v
        .get("tokens")
        .ok_or_else(|| Error::Config("~/.codex/auth.json missing 'tokens'".into()))?;

    let access_token = tokens
        .get("access_token")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Config("~/.codex/auth.json missing tokens.access_token".into()))?
        .to_string();
    let refresh_token = tokens
        .get("refresh_token")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Config("~/.codex/auth.json missing tokens.refresh_token".into()))?
        .to_string();
    let account_id = tokens
        .get("account_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Config("~/.codex/auth.json missing tokens.account_id".into()))?
        .to_string();

    // Derive expires_at from JWT `exp` claim, or fall back to now + 28d.
    let expires_at = extract_jwt_exp(&access_token).unwrap_or_else(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        now + 60 * 60 * 24 * 28
    });

    let auth = CodexAuth {
        access_token,
        refresh_token,
        expires_at,
        account_id,
    };
    save_for_profile(profile, &auth)?;
    Ok(Some(auth))
}

/// Decode a JWT's `exp` claim. Returns None on any parse failure — the
/// caller falls back to a long-default expiry.
fn extract_jwt_exp(jwt: &str) -> Option<i64> {
    use base64::Engine;
    let payload_b64 = jwt.split('.').nth(1)?;
    let padded = match payload_b64.len() % 4 {
        2 => format!("{payload_b64}=="),
        3 => format!("{payload_b64}="),
        _ => payload_b64.to_string(),
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&padded))
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    payload.get("exp")?.as_i64()
}

/// Auth-resolution chain for the `ChatGptCodex` provider:
/// 1. Per-profile file `~/.config/thclaws/auth/<profile>.json`
/// 2. Legacy `~/.config/thclaws/auth.json` (auto-migrate)
/// 3. Official Codex CLI's `~/.codex/auth.json` (auto-import)
/// 4. Return None — caller must error with a "run codex login first" hint.
pub fn resolve_for_profile(profile: &str) -> Result<Option<CodexAuth>> {
    if let Some(auth) = load_for_profile(profile)? {
        return Ok(Some(auth));
    }
    if let Some(auth) = migrate_legacy_to_profile(profile)? {
        return Ok(Some(auth));
    }
    import_from_codex_cli(profile)
}
