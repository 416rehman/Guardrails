# AI-assisted contributions

Guardrails ADR is built by AI coding agents, which plan, write, review and
release it with no required human step. This policy applies the same rules
to those agents and to everyone else. It is changed only by RFC.

## The rules

1. Every contribution has a responsible author: a person, or the project
   agent named in its pull request. The merge queue lands every change, so
   nobody holds a merge right. A review counts only when it comes from a
   reviewer that did not write the change. Agents hold no code-owner entry,
   no entry in MAINTAINERS.md and no vote in the steering group.

2. Every code change links an accepted work item. Agents do not open
   unsolicited pull requests to this project or to anyone else's.

3. Every pull request says whether AI was used, in its metadata block:
   the tool and model that produced the text (for example
   claude-code:claude-opus-5-5), or none when no AI tool wrote any of it.
   Name the tool and model that produced the text, not every tool you had
   open. Commit messages and pull-request descriptions written by a tool
   count.

4. Every pull request carries the evidence template from CONTRIBUTING.md,
   with command output, not claims. Say what you could not verify.

5. There is no sign-off. Commit messages are one line, and no commit
   carries Signed-off-by, Co-Authored-By or any other trailer.

## What opening a pull request means

By opening a pull request you submit the contribution under the project's
licence (Apache-2.0 section 5) and confirm that you have the right to.
When a tool wrote part of it, you confirm that:

- the tool's terms of use allow you to contribute its output under
  Apache-2.0;
- you did not feed it, and it did not fetch, material from sources on the
  do-not-read list (supply-chain/do-not-read.toml) or other code you may
  not relicense;
- the output does not, to your knowledge, reproduce third-party code or
  rules under an incompatible licence.

This is not a statement that you read every line. Review depth is set by
the change's risk tier and recorded in the pull request.

## How the project's own agents land changes

The steward's agents commit on agent branches with one-line commit
messages. Each pull request names its work item and the model that wrote
it. The merge queue squash-merges it once verify and CI pass on the
rebased branch, every review its risk tier requires has passed, at most
three review rounds were used and the branch is current. Reviews run in a
clean context, and the cross-model review runs on the model that did not
write the change. Every check run and review is recorded on the pull
request.

Risk tiers: a change that deterministic checks can prove (comments,
formatting, prose) lands on those checks alone; a small change gets one
review pass; other changes get their tier's reviews; high-risk changes and
every trust-core change get the security and adversarial reviews, and a
trust-core change needs two independent passing reviews on different
models.

## Quality bar

We close contributions, from anyone, that cost more to review than they
are worth, with the label "extractive" and a reason. Common reasons:
generated changes with no linked work item; tests that cannot fail; code
that wraps what it claims to remove; large diffs with no evidence. Size the
change to what a reviewer can check.

## Same gate for everyone

Pull requests from people and from the project's agents pass the same
public `verify`. The held-out suite scores every change on the main branch
nightly, whoever wrote it. The project's own agent work is also scored
before merge, because it is produced in volume; anyone else may ask for the
same pre-merge run.

## Security reports

AI-found vulnerabilities are welcome through SECURITY.md if they come with
a reproducer and a statement of what you could not test. Reports without a
reproducer are closed.

## Contributing elsewhere

When we contribute to other projects we follow their AI policy, including
their trailer rules, and a person is always the author of record.
