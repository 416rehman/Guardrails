//! Squashing a tree into the queue's worktree and starting its verify on a thread of its own, so
//! the dispatcher's loop keeps polling its sessions while git rewrites that worktree.

use std::thread::{self, JoinHandle};

use anyhow::{Result, anyhow};

use super::{Prepared, QueueConfig, Tree, Writer, start};
use crate::repo::Repo;

/// The queue's worktree being readied for one tree's verify.
pub struct Preparing {
    pub tree: Tree,
    /// The item left review while it was readied, so a started verify is stopped at once.
    pub cancelled: bool,
    handle: JoinHandle<Result<Prepared>>,
}

impl Preparing {
    /// Starts readying `tree` for its verify as `writer`, and returns at once.
    pub fn begin(repo: &Repo, config: &QueueConfig, tree: &Tree, writer: &Writer) -> Preparing {
        let (repo, config, owned, writer) =
            (repo.clone(), config.clone(), tree.clone(), writer.clone());
        Preparing {
            tree: tree.clone(),
            cancelled: false,
            handle: thread::spawn(move || start(&repo, &config, &owned, &writer)),
        }
    }

    pub fn finished(&self) -> bool {
        self.handle.is_finished()
    }

    /// What readying the tree gave; waits when it has not finished.
    pub fn finish(self) -> Result<Prepared> {
        self.handle
            .join()
            .map_err(|_| anyhow!("readying the queue's worktree stopped unexpectedly"))?
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::dispatch::landing_tests::{
        push_and_open, to_review, until_verified, valid_body, with_origin,
    };
    use crate::dispatch::tests::Setup;
    use crate::orchestrate::testkit::{FakeProgram, git, write_program};
    use crate::testkit::TempRepo;

    /// Makes git's checkout of the queue worktree wait until `markers/release` exists, for at
    /// most twenty seconds, and then write `markers/done`.
    fn hold_queue_checkout(setup: &Setup, markers: &Path) {
        let dir = markers.to_string_lossy().replace('\\', "/");
        let hook = format!(
            "#!/bin/sh\ncase \"$PWD\" in\n*/queue)\n  i=0\n  while [ ! -f \"{dir}/release\" ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done\n  : > \"{dir}/done\"\n  ;;\nesac\n"
        );
        let hooks = markers.join("hooks");
        fs::create_dir_all(&hooks).unwrap();
        write_program(&hooks.join("post-checkout"), &hook);
        let hooks = hooks.to_string_lossy().replace('\\', "/");
        git(setup.temp.root(), &["config", "core.hooksPath", &hooks]);
    }

    #[test]
    fn the_review_pass_returns_while_git_readies_the_queue_worktree() {
        let setup = Setup::new("");
        let _origin = with_origin(&setup);
        let verify = FakeProgram::new("queue-verify");
        verify.respond(1, "verify: green\n", 0);
        let mut dispatcher = to_review(&setup, 62, "guide.md");
        dispatcher.set_verifier(verify.program().to_path_buf());
        push_and_open(&setup, 62, "docs: add the guide", &valid_body(62));
        let markers = TempRepo::create();
        hold_queue_checkout(&setup, markers.root());
        dispatcher.step_github().unwrap();
        assert!(
            !markers.root().join("done").exists(),
            "the review pass waited for git to ready the queue worktree"
        );
        assert!(!dispatcher.idle(), "the queue holds the tree it readies");
        fs::write(markers.root().join("release"), "").unwrap();
        until_verified(&mut dispatcher);
        assert!(markers.root().join("done").exists());
        assert_eq!(verify.calls().len(), 1, "{:?}", verify.calls());
    }
}
