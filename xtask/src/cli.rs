//! Argument parsing for subcommands: known flags, options with values, positional arguments.

use anyhow::{Result, bail};

pub struct Spec<'a> {
    pub flags: &'a [&'a str],
    pub options: &'a [&'a str],
}

#[derive(Debug, Default)]
pub struct Parsed {
    flags: Vec<String>,
    values: Vec<(String, String)>,
    pub positional: Vec<String>,
}

impl Parsed {
    pub fn has(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }

    pub fn value(&self, option: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(name, _)| name == option)
            .map(|(_, value)| value.as_str())
    }
}

pub fn parse(args: &[String], spec: &Spec) -> Result<Parsed> {
    let mut parsed = Parsed::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            parsed.positional.extend(iter.by_ref().cloned());
            break;
        }
        if let Some((name, value)) = arg.split_once('=')
            && spec.options.contains(&name)
        {
            parsed.values.push((name.to_owned(), value.to_owned()));
        } else if spec.flags.contains(&arg.as_str()) {
            parsed.flags.push(arg.clone());
        } else if spec.options.contains(&arg.as_str()) {
            let Some(value) = iter.next() else {
                bail!("{arg} needs a value");
            };
            parsed.values.push((arg.clone(), value.clone()));
        } else if arg.starts_with('-') {
            bail!("unknown option {arg}");
        } else {
            parsed.positional.push(arg.clone());
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: Spec = Spec {
        flags: &["--fast"],
        options: &["--json", "--base"],
    };

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_options_and_positionals() {
        let parsed = parse(
            &args(&["--fast", "--json", "out.json", "--base=main", "a.rs"]),
            &SPEC,
        )
        .unwrap();
        assert!(parsed.has("--fast"));
        assert_eq!(parsed.value("--json"), Some("out.json"));
        assert_eq!(parsed.value("--base"), Some("main"));
        assert_eq!(parsed.positional, vec!["a.rs"]);
    }

    #[test]
    fn rejects_unknown_and_missing_values() {
        assert!(parse(&args(&["--slow"]), &SPEC).is_err());
        assert!(parse(&args(&["--json"]), &SPEC).is_err());
    }
}
