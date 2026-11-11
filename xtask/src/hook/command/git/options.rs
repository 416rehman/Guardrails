//! git's long options as git reads them: any unambiguous prefix of a long option names it, so
//! `--trai` is `--trailer` and `--no-veri` is `--no-verify`. The tables are the long options of
//! `git commit` and `git push` as `--git-completion-helper-all` lists them for git 2.52, negated
//! forms included; a prefix of none of them, or of several, is not resolved.

const COMMIT: &[&str] = &[
    "--ahead-behind",
    "--all",
    "--allow-empty",
    "--allow-empty-message",
    "--amend",
    "--author",
    "--branch",
    "--cleanup",
    "--date",
    "--dry-run",
    "--edit",
    "--file",
    "--fixup",
    "--gpg-sign",
    "--include",
    "--inter-hunk-context",
    "--interactive",
    "--long",
    "--message",
    "--no-ahead-behind",
    "--no-all",
    "--no-allow-empty",
    "--no-allow-empty-message",
    "--no-amend",
    "--no-author",
    "--no-branch",
    "--no-cleanup",
    "--no-date",
    "--no-dry-run",
    "--no-edit",
    "--no-file",
    "--no-fixup",
    "--no-gpg-sign",
    "--no-include",
    "--no-interactive",
    "--no-long",
    "--no-message",
    "--no-null",
    "--no-only",
    "--no-patch",
    "--no-pathspec-file-nul",
    "--no-pathspec-from-file",
    "--no-porcelain",
    "--no-post-rewrite",
    "--no-quiet",
    "--no-reedit-message",
    "--no-reset-author",
    "--no-reuse-message",
    "--no-short",
    "--no-signoff",
    "--no-squash",
    "--no-status",
    "--no-template",
    "--no-untracked-files",
    "--no-verbose",
    "--no-verify",
    "--null",
    "--only",
    "--patch",
    "--pathspec-file-nul",
    "--pathspec-from-file",
    "--porcelain",
    "--post-rewrite",
    "--quiet",
    "--reedit-message",
    "--reset-author",
    "--reuse-message",
    "--short",
    "--signoff",
    "--squash",
    "--status",
    "--template",
    "--trailer",
    "--unified",
    "--untracked-files",
    "--verbose",
    "--verify",
];

const PUSH: &[&str] = &[
    "--all",
    "--atomic",
    "--branches",
    "--delete",
    "--dry-run",
    "--exec",
    "--follow-tags",
    "--force",
    "--force-if-includes",
    "--force-with-lease",
    "--ipv4",
    "--ipv6",
    "--mirror",
    "--no-all",
    "--no-atomic",
    "--no-branches",
    "--no-delete",
    "--no-dry-run",
    "--no-exec",
    "--no-follow-tags",
    "--no-force",
    "--no-force-if-includes",
    "--no-force-with-lease",
    "--no-mirror",
    "--no-porcelain",
    "--no-progress",
    "--no-prune",
    "--no-push-option",
    "--no-quiet",
    "--no-receive-pack",
    "--no-recurse-submodules",
    "--no-repo",
    "--no-set-upstream",
    "--no-signed",
    "--no-tags",
    "--no-thin",
    "--no-verbose",
    "--no-verify",
    "--porcelain",
    "--progress",
    "--prune",
    "--push-option",
    "--quiet",
    "--receive-pack",
    "--recurse-submodules",
    "--repo",
    "--set-upstream",
    "--signed",
    "--tags",
    "--thin",
    "--verbose",
    "--verify",
];

/// The subcommands whose long options are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Subcommand {
    Commit,
    Push,
}

/// A long option as git resolves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LongOption {
    /// The full name, with its `--`.
    Known(&'static str),
    /// No option, or more than one, starts with the name; git refuses it.
    Unresolved,
}

impl Subcommand {
    pub(super) fn of(name: &str) -> Option<Subcommand> {
        match name {
            "commit" => Some(Subcommand::Commit),
            "push" => Some(Subcommand::Push),
            _ => None,
        }
    }

    fn options(self) -> &'static [&'static str] {
        match self {
            Subcommand::Commit => COMMIT,
            Subcommand::Push => PUSH,
        }
    }

    /// `word` (`--name` or `--name=value`) resolved to its option.
    pub(super) fn resolve(self, word: &str) -> LongOption {
        let name = word.split('=').next().unwrap_or_default();
        let options = self.options();
        if let Some(exact) = options.iter().find(|option| **option == name) {
            return LongOption::Known(exact);
        }
        let mut found = options.iter().filter(|option| option.starts_with(name));
        match (found.next(), found.next()) {
            (Some(only), None) => LongOption::Known(only),
            _ => LongOption::Unresolved,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_resolve_to_their_option() {
        let commit = Subcommand::Commit;
        assert_eq!(commit.resolve("--trai"), LongOption::Known("--trailer"));
        assert_eq!(commit.resolve("--sign"), LongOption::Known("--signoff"));
        assert_eq!(
            commit.resolve("--no-veri"),
            LongOption::Known("--no-verify")
        );
        assert_eq!(
            commit.resolve("--mess=fix: x"),
            LongOption::Known("--message")
        );
        assert_eq!(commit.resolve("--all"), LongOption::Known("--all"));
        assert_eq!(commit.resolve("--a"), LongOption::Unresolved);
        assert_eq!(commit.resolve("--nonsense"), LongOption::Unresolved);
        assert_eq!(Subcommand::Push.resolve("--forc"), LongOption::Unresolved);
        assert_eq!(
            Subcommand::Push.resolve("--force-w"),
            LongOption::Known("--force-with-lease")
        );
    }
}
