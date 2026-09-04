//! Authorization gating for Firelin's active scanning commands.
//!
//! Scan commands (`portscan`, `subdns`, `dirscan`) touch remote systems. They
//! refuse to run until the operator confirms — via the CLI flag
//! `--yes-i-have-permission` or the environment variable
//! `FIRELIN_I_HAVE_PERMISSION=yes` — that the target is owned or covered by
//! written permission. `fingerprint` and `cidr` are read-only/single-request
//! helpers and are not gated.

use std::env;

/// CLI flag that confirms authorization for active scanning.
pub const PERMISSION_FLAG: &str = "--yes-i-have-permission";

/// Environment variable that confirms authorization for active scanning.
pub const PERMISSION_ENV: &str = "FIRELIN_I_HAVE_PERMISSION";

/// True when scanning is authorized for this invocation: the CLI flag was
/// passed, or the environment variable holds "yes" (trimmed, case-insensitive).
pub fn confirmed(flag: bool) -> bool {
    flag || env_allows()
}

/// True when `FIRELIN_I_HAVE_PERMISSION` is set to "yes".
pub fn env_allows() -> bool {
    match env::var(PERMISSION_ENV) {
        Ok(value) => value.trim().eq_ignore_ascii_case("yes"),
        Err(_) => false,
    }
}

/// The prominent notice printed (to stderr) when a scan command is refused.
pub const NOTICE: &str = "\
======================================================================
 FIRELIN - AUTHORIZATION REQUIRED
======================================================================
Active scanning commands (portscan / subdns / dirscan) send traffic
to the target. You must confirm that you OWN the target or have
WRITTEN PERMISSION to test it before Firelin will run.

How to confirm:
  * append the flag:         --yes-i-have-permission
  * or set the environment:  FIRELIN_I_HAVE_PERMISSION=yes

Example:
  firelin portscan 192.168.1.0/24 --yes-i-have-permission

Scanning systems without authorization is illegal in most
jurisdictions. Firelin is for authorized security assessments only.
======================================================================";

/// The short one-line error carried in JSON error output and stderr.
pub fn denial_message(command: &str) -> String {
    format!(
        "command '{command}' requires authorization confirmation: pass {PERMISSION_FLAG} or set {PERMISSION_ENV}=yes"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// The process environment is shared, so env-touching tests must run
    /// one at a time (cargo runs unit tests in parallel threads).
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn clear_env() {
        env::remove_var(PERMISSION_ENV);
    }

    #[test]
    fn flag_confirms_regardless_of_env() {
        let _guard = env_lock();
        clear_env();
        assert!(confirmed(true));
        env::set_var(PERMISSION_ENV, "no");
        assert!(confirmed(true), "the explicit flag must always win");
        clear_env();
    }

    #[test]
    fn denied_without_flag_or_env() {
        let _guard = env_lock();
        clear_env();
        assert!(!confirmed(false));
        assert!(!env_allows());
    }

    #[test]
    fn env_yes_confirms() {
        let _guard = env_lock();
        env::set_var(PERMISSION_ENV, "yes");
        assert!(confirmed(false));
        assert!(env_allows());
        env::set_var(PERMISSION_ENV, "YES");
        assert!(env_allows(), "case-insensitive yes is accepted");
        clear_env();
    }

    #[test]
    fn env_other_values_denied() {
        let _guard = env_lock();
        for value in ["no", "true", "1", "", "please"] {
            env::set_var(PERMISSION_ENV, value);
            assert!(!env_allows(), "value '{value}' must not confirm");
        }
        clear_env();
    }
}
