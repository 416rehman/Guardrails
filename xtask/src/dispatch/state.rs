//! What the dispatcher remembers between runs, in the git-ignored `.agent/state/`: when each
//! routine last started and which planning and review sessions already ran. A file that does not
//! parse stops the dispatcher with its path instead of reading as empty, because an empty record
//! starts every routine at once and plans and reviews every issue again. A save goes through a
//! staged copy and a rename, so a crash never leaves half a file.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::repo::{Repo, write_if_changed};

const STAGED_SUFFIX: &str = ".partial";

/// `relative` parsed, or the empty record while the file does not exist yet.
pub fn load<T: DeserializeOwned + Default>(repo: &Repo, relative: &str) -> Result<T> {
    let Some(text) = repo.read_optional(relative)? else {
        return Ok(T::default());
    };
    serde_json::from_str(&text).with_context(|| {
        format!(
            "{relative} does not parse, and reading it as empty would run its routines, plans and reviews again; repair it, or delete it to accept that rerun, then start the dispatcher again"
        )
    })
}

pub fn save<T: Serialize>(repo: &Repo, relative: &str, value: &T) -> Result<()> {
    let mut json = serde_json::to_string_pretty(value)?;
    json.push('\n');
    let path = repo.path(relative);
    if fs::read(&path).is_ok_and(|current| current == json.as_bytes()) {
        return Ok(());
    }
    let mut staged = OsString::from(path.as_os_str());
    staged.push(STAGED_SUFFIX);
    let staged = PathBuf::from(staged);
    write_if_changed(&staged, json.as_bytes())?;
    fs::rename(&staged, &path).with_context(|| format!("replacing {relative}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::testkit::TempRepo;

    const FILE: &str = ".agent/state/record.json";

    #[test]
    fn an_absent_file_is_empty_and_a_saved_one_reads_back() {
        let temp = TempRepo::create();
        let empty: BTreeMap<String, u64> = load(&temp.repo(), FILE).unwrap();
        assert!(empty.is_empty());
        let record = BTreeMap::from([("garden-docs".to_owned(), 7u64)]);
        save(&temp.repo(), FILE, &record).unwrap();
        assert_eq!(
            load::<BTreeMap<String, u64>>(&temp.repo(), FILE).unwrap(),
            record
        );
        assert!(!temp.root().join(format!("{FILE}{STAGED_SUFFIX}")).exists());
    }

    #[test]
    fn a_file_that_does_not_parse_names_itself() {
        let temp = TempRepo::create();
        temp.write(FILE, "{\"garden-docs\": 7");
        let error = load::<BTreeMap<String, u64>>(&temp.repo(), FILE).unwrap_err();
        assert!(format!("{error:#}").contains(FILE), "{error:#}");
    }
}
