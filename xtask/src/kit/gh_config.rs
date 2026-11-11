//! Where `gh` keeps its configuration, `hosts.yml` with the login and token among it, as `gh`
//! finds it: `GH_CONFIG_DIR`, else `gh` in `XDG_CONFIG_HOME`, else on Windows `GitHub CLI` in
//! `APPDATA`, else `.config/gh` in the home directory. The guards refuse every one of them a
//! session's variables point at, since a command can unset a variable for the `gh` it runs.

use std::path::{Path, PathBuf};

/// A variable that places `gh`'s configuration directory, and the folder `gh` uses inside it,
/// if it uses one.
const LOCATIONS: &[(&str, Option<&str>)] = &[
    ("GH_CONFIG_DIR", None),
    ("XDG_CONFIG_HOME", Some("gh")),
    ("APPDATA", Some("GitHub CLI")),
];
/// The directory below the home directory when no variable places it.
const HOME_LOCATION: &[&str] = &[".config", "gh"];

/// Every directory `gh` may read its configuration from with the variables `lookup` reads, and the
/// one below each of `homes`.
pub fn config_dirs(lookup: impl Fn(&str) -> Option<String>, homes: &[PathBuf]) -> Vec<PathBuf> {
    let placed = LOCATIONS.iter().filter_map(|(variable, folder)| {
        lookup(variable)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| match folder {
                Some(folder) => Path::new(&value).join(folder),
                None => PathBuf::from(value),
            })
    });
    let below_home = homes.iter().map(|home| {
        HOME_LOCATION
            .iter()
            .fold(home.clone(), |dir, part| dir.join(part))
    });
    placed.chain(below_home).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_location_a_variable_names_and_the_home_fallback() {
        let set = |name: &str| match name {
            "GH_CONFIG_DIR" => Some("/cfg/gh".to_owned()),
            "XDG_CONFIG_HOME" => Some("/xdg".to_owned()),
            "APPDATA" => Some(r"C:\Users\dev\AppData\Roaming".to_owned()),
            _ => None,
        };
        let found = config_dirs(set, &[PathBuf::from("/home/dev")]);
        assert_eq!(
            found,
            vec![
                PathBuf::from("/cfg/gh"),
                Path::new("/xdg").join("gh"),
                Path::new(r"C:\Users\dev\AppData\Roaming").join("GitHub CLI"),
                Path::new("/home/dev").join(".config").join("gh"),
            ]
        );
        let blank = |name: &str| (name == "GH_CONFIG_DIR").then(|| " ".to_owned());
        assert_eq!(config_dirs(blank, &[]), Vec::<PathBuf>::new());
    }
}
