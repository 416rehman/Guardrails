//! Where Claude Code keeps its user configuration: `CLAUDE_CONFIG_DIR`, else `.claude` in the
//! home directory, which is `USERPROFILE` on Windows and `HOME` elsewhere, as Claude Code finds
//! it. Its global config file sits in `CLAUDE_CONFIG_DIR` too, else in the home directory itself.
//! The kit commands and the hook handlers all read it here, so they agree on the user settings,
//! the plugin cache, the installed-plugin record and the workspace trust. None of these
//! directories need exist.

use std::path::PathBuf;

pub const CONFIG_DIR_VARIABLE: &str = "CLAUDE_CONFIG_DIR";
pub const CONFIG_DIR_NAME: &str = ".claude";
pub const HOME_VARIABLE: &str = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
pub const USER_SETTINGS_FILE: &str = "settings.json";

/// The home directory Claude Code reads.
pub fn home(lookup: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    variable(&lookup, HOME_VARIABLE).map(PathBuf::from)
}

/// The configuration directory.
pub fn config_dir(lookup: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    variable(&lookup, CONFIG_DIR_VARIABLE)
        .map(PathBuf::from)
        .or_else(|| home(&lookup).map(|home| home.join(CONFIG_DIR_NAME)))
}

/// The directory that holds the global config file, `.claude.json`.
pub fn global_config_dir(lookup: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    variable(&lookup, CONFIG_DIR_VARIABLE)
        .map(PathBuf::from)
        .or_else(|| home(&lookup))
}

/// The user settings file in [`config_dir`].
pub fn user_settings(lookup: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    config_dir(lookup).map(|dir| dir.join(USER_SETTINGS_FILE))
}

/// A variable of this process, for the commands that run outside a hook.
pub fn process_variable(name: &str) -> Option<String> {
    std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
}

/// `name` as `lookup` reads it, trimmed; an empty value is unset.
fn variable(lookup: impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<String> + 'a {
        |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn the_variable_wins_then_the_platform_home() {
        let both_homes = [("HOME", "/h/home"), ("USERPROFILE", "/h/profile")];
        let home = if cfg!(windows) {
            "/h/profile"
        } else {
            "/h/home"
        };
        assert_eq!(
            config_dir(lookup(&both_homes)),
            Some(PathBuf::from(home).join(CONFIG_DIR_NAME))
        );
        let set = [
            (CONFIG_DIR_VARIABLE, "/cfg"),
            ("HOME", "/h"),
            ("USERPROFILE", "/h"),
        ];
        assert_eq!(config_dir(lookup(&set)), Some(PathBuf::from("/cfg")));
        assert_eq!(
            user_settings(lookup(&set)),
            Some(PathBuf::from("/cfg").join(USER_SETTINGS_FILE))
        );
    }

    #[test]
    fn empty_values_are_skipped() {
        let empty = [(CONFIG_DIR_VARIABLE, " "), (HOME_VARIABLE, "/h")];
        assert_eq!(
            config_dir(lookup(&empty)),
            Some(PathBuf::from("/h").join(CONFIG_DIR_NAME))
        );
        assert_eq!(config_dir(lookup(&[(HOME_VARIABLE, "")])), None);
    }

    #[test]
    fn the_global_config_sits_in_the_config_dir_or_the_home_directory() {
        let set = [(CONFIG_DIR_VARIABLE, "/cfg"), (HOME_VARIABLE, "/h")];
        assert_eq!(global_config_dir(lookup(&set)), Some(PathBuf::from("/cfg")));
        let unset = [(CONFIG_DIR_VARIABLE, ""), (HOME_VARIABLE, "/h")];
        assert_eq!(global_config_dir(lookup(&unset)), Some(PathBuf::from("/h")));
        assert_eq!(global_config_dir(lookup(&[])), None);
    }
}
