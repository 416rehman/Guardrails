//! Check S3: a new comment line must carry a reason the code cannot show (owner instruction 4,
//! rule 4). Narration, change-log and step comments, commented-out code and a TODO without a
//! work-item id are findings. Doc comments are judged only on their TODOs.

use std::sync::LazyLock;

use super::patterns::{Compiled, compile, is_match};

const DIRECTIVES: &[&str] = &[
    "SAFETY:",
    "SPDX-",
    "@ts-",
    "eslint-",
    "biome-ignore",
    "prettier-ignore",
    "rustfmt::",
    "noqa",
    "language=",
    "#region",
    "#endregion",
];
const CODE_ENDINGS: &[&str] = &[";", "{", "}", "),", "],"];
const CODE_MARKS: &[&str] = &["(", "=", "::", "->", "[", "{", "}"];

static TODO: Compiled =
    LazyLock::new(|| compile(r"(?i:^(todo|fixme|xxx|hack)\b)|\b(TODO|FIXME|XXX|HACK)\s*[:(]"));
static WORK_ITEM: Compiled = LazyLock::new(|| compile(r"WI-\d{4}|#\d+"));
static CHANGE_LOG_START: Compiled = LazyLock::new(|| {
    compile(
        r"(?i)^(added|removed|changed|updated|fixed|refactored|renamed|moved|replaced|deleted|introduced|reworked|switched|bumped|reverted)\b",
    )
});
static CHANGE_LOG_ANYWHERE: Compiled = LazyLock::new(|| {
    compile(
        r"(?i)\b(previously|was (changed|added|removed|renamed|moved|replaced|refactored)|(this|the) (pr|commit|patch)\b|old (code|version|implementation)|new (code|implementation))",
    )
});
static CODE_START: Compiled = LazyLock::new(|| {
    compile(
        r"^(let|const|var|fn|pub|use|impl|struct|enum|mod|match|return|import|export|function|if|for|while)\s",
    )
});
static CALL: Compiled = LazyLock::new(|| compile(r"[A-Za-z_][\w:.]*\(.*\)\s*;?$"));
static STEP: Compiled = LazyLock::new(|| compile(r"(?i)^(step\s*\d+\b|\d+[.)]\s|\(\d+\)\s)"));
static REASON: Compiled = LazyLock::new(|| {
    compile(
        r"(?i)\b(because|since|so that|so the|otherwise|unless|invariant|must|never|only|safety|see|requires?|guarantees?|assumes?|avoids?|prevents?|in case|instead|rather than|when|while|until|if|why)\b|https?://|\bRFC\b|ADR-\d+|\bD-\d+\b|WI-\d{4}|#\d+|\b(team|design)/\d+",
    )
});
static NARRATION: Compiled = LazyLock::new(|| {
    compile(
        r"(?i)^((now|then|next|first|finally|here|we|let's|lets)\b|this (function|method|line|block|loop|code|helper)\b|(create|get|set|initiali[sz]e|check|loop|iterate|call|return|increment|parse|build|update|handle|compute|calculate|convert|read|write|open|close|add|remove|start|stop|load|save|send|fetch|print|store|append|push|split|sort|find|collect|skip)(s|es)?\s+(the|a|an|all|each|every|new|our|this|that|it|them|its|over|through)\b)",
    )
});

/// The reason a comment line fails S3, or `None` when it may stay.
pub fn classify(text: &str, doc: bool) -> Option<&'static str> {
    let text = text.trim();
    if text.is_empty()
        || DIRECTIVES
            .iter()
            .any(|directive| text.starts_with(directive))
    {
        return None;
    }
    if is_match(&TODO, text) && !is_match(&WORK_ITEM, text) {
        return Some("TODO without a work-item id (WI-NNNN or #<issue>)");
    }
    if doc {
        return None;
    }
    if is_match(&CHANGE_LOG_START, text) || is_match(&CHANGE_LOG_ANYWHERE, text) {
        return Some("change-log comment; history belongs in the commit");
    }
    if looks_like_code(text) {
        return Some("commented-out code; delete it, git keeps it");
    }
    if is_match(&STEP, text) {
        return Some("step comment; extract a named function instead");
    }
    if is_match(&REASON, text) {
        return None;
    }
    if is_match(&NARRATION, text) {
        return Some("narration; the code already says what it does");
    }
    None
}

fn looks_like_code(text: &str) -> bool {
    if text.starts_with("#[") || text.starts_with("#![") {
        return true;
    }
    let ends_like_code = CODE_ENDINGS.iter().any(|ending| text.ends_with(ending));
    let marked = CODE_MARKS.iter().any(|mark| text.contains(mark));
    if ends_like_code && marked {
        return true;
    }
    let statement =
        text.contains(" = ") || text.contains("=>") || text.contains("::") || is_match(&CALL, text);
    is_match(&CODE_START, text) && statement
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        assert!(super::super::patterns::all_compile(&[
            &TODO,
            &WORK_ITEM,
            &CHANGE_LOG_START,
            &CHANGE_LOG_ANYWHERE,
            &CODE_START,
            &CALL,
            &STEP,
            &REASON,
            &NARRATION,
        ]));
    }

    #[test]
    fn reasons_and_directives_stay() {
        for comment in [
            "SAFETY: the pointer outlives the call.",
            "Claude Code ignores unknown fields, so the renderer rejects them.",
            "Windows cannot replace a running executable; rename it first.",
            "Spec: https://code.claude.com/docs/en/hooks",
            "D-47: the base branch builds the kit binary.",
            "TODO(WI-0012): drop once the dispatcher lands.",
            "TODO #41 remove the fallback",
            "Invariant: ids are unique per tenant.",
            "Exit 2 blocks the tool call.",
        ] {
            assert_eq!(classify(comment, false), None, "{comment}");
        }
    }

    #[test]
    fn narration_change_log_steps_and_code_fail() {
        let cases = [
            ("Create the client", "narration"),
            ("Loop over all items", "narration"),
            ("Now we parse the input", "narration"),
            ("Added retry logic", "change-log"),
            ("Previously this used a Vec", "change-log"),
            ("Step 2: write the file", "step"),
            ("1. Parse the header", "step"),
            ("let x = compute(y);", "commented-out"),
            ("foo.bar(baz);", "commented-out"),
            ("if ready {", "commented-out"),
            ("#[derive(Debug)]", "commented-out"),
            ("TODO: handle errors", "TODO"),
            ("FIXME later", "TODO"),
        ];
        for (comment, expected) in cases {
            let reason = classify(comment, false).unwrap_or("none");
            assert!(reason.starts_with(expected), "{comment}: {reason}");
        }
    }

    #[test]
    fn doc_comments_are_judged_only_on_todos() {
        assert_eq!(classify("Returns the first match.", true), None);
        assert!(classify("TODO: document", true).is_some());
        assert!(classify("Retry later. FIXME(net): flaky", true).is_some());
        assert_eq!(
            classify("A TODO without a work-item id is a finding.", true),
            None
        );
    }
}
