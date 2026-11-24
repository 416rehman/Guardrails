// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::{ColumnDef, EntitySchema, SchemaDataClass};

type RawColumnSpec<'a> = (&'a str, SchemaDataClass, &'a str, bool);
type RawEntitySpec<'a> = (&'a str, &'a str, &'a [RawColumnSpec<'a>]);

const ENTITY_CATALOG: &[RawEntitySpec<'_>] = &[
    (
        "sessions",
        "Observed coding-agent sessions with attribution, denial counts, and labels.",
        &[
            (
                "id",
                SchemaDataClass::Metadata,
                "Unique session identifier",
                false,
            ),
            (
                "device_id",
                SchemaDataClass::Metadata,
                "Device identifier",
                false,
            ),
            (
                "device_name",
                SchemaDataClass::Metadata,
                "Device hostname",
                false,
            ),
            (
                "agent_name",
                SchemaDataClass::Metadata,
                "Coding agent harness",
                false,
            ),
            (
                "pseudonym_id",
                SchemaDataClass::Metadata,
                "Privacy-safe actor token",
                false,
            ),
            (
                "user_id",
                SchemaDataClass::NamedIdentity,
                "Organization user ID",
                false,
            ),
            (
                "user_display",
                SchemaDataClass::NamedIdentity,
                "Human user display name",
                false,
            ),
            (
                "total_actions",
                SchemaDataClass::Metadata,
                "Action attempt count",
                false,
            ),
            (
                "blocked_count",
                SchemaDataClass::Metadata,
                "Denied action count",
                false,
            ),
            (
                "assurance_level",
                SchemaDataClass::Metadata,
                "Effective enforcement level",
                false,
            ),
            (
                "prompt_body",
                SchemaDataClass::Content,
                "Raw user prompt text",
                true,
            ),
        ],
    ),
    (
        "attempts",
        "Individual tool invocations and shell commands intercepted by hooks or proxies.",
        &[
            ("id", SchemaDataClass::Metadata, "Attempt identifier", false),
            (
                "session_id",
                SchemaDataClass::Metadata,
                "Parent session identifier",
                false,
            ),
            ("agent_name", SchemaDataClass::Metadata, "Agent name", false),
            (
                "action_class",
                SchemaDataClass::Metadata,
                "Action classification",
                false,
            ),
            (
                "control_point",
                SchemaDataClass::Metadata,
                "Enforcement point",
                false,
            ),
            (
                "target",
                SchemaDataClass::Metadata,
                "Sanitized path, host, or command",
                false,
            ),
            (
                "user_display",
                SchemaDataClass::NamedIdentity,
                "User attributed to turn",
                false,
            ),
            (
                "turn_index",
                SchemaDataClass::Metadata,
                "1-based conversation turn",
                false,
            ),
            (
                "prompt_body",
                SchemaDataClass::Content,
                "Full model/user turn text",
                true,
            ),
            (
                "raw_secret",
                SchemaDataClass::Secret,
                "Never queryable credential bytes",
                true,
            ),
        ],
    ),
    (
        "users",
        "Directory-resolved people with risk scores and activity rollups.",
        &[
            (
                "id",
                SchemaDataClass::Metadata,
                "Stable directory user key",
                false,
            ),
            (
                "pseudonym_id",
                SchemaDataClass::Metadata,
                "Works-council pseudonym",
                false,
            ),
            (
                "display_name",
                SchemaDataClass::NamedIdentity,
                "Full name",
                false,
            ),
            (
                "user_email",
                SchemaDataClass::NamedIdentity,
                "Corporate email address",
                true,
            ),
            (
                "department",
                SchemaDataClass::Metadata,
                "Organizational unit",
                false,
            ),
            (
                "risk_score",
                SchemaDataClass::Metadata,
                "Additive risk index (0-100)",
                false,
            ),
            (
                "risk_tier",
                SchemaDataClass::Metadata,
                "Low, elevated, high, or critical",
                false,
            ),
            (
                "blocked_count",
                SchemaDataClass::Metadata,
                "Blocked actions across devices",
                false,
            ),
        ],
    ),
    (
        "artifacts",
        "Discovered agent instructions, skills, rules, commands, and plugins.",
        &[
            (
                "id",
                SchemaDataClass::Metadata,
                "Artifact identifier",
                false,
            ),
            (
                "name",
                SchemaDataClass::Metadata,
                "Skill or rule file name",
                false,
            ),
            ("kind", SchemaDataClass::Metadata, "Artifact type", false),
            (
                "scope",
                SchemaDataClass::Metadata,
                "User, workspace, or managed scope",
                false,
            ),
            (
                "source_agent",
                SchemaDataClass::Metadata,
                "Host coding agent",
                false,
            ),
            (
                "content_digest",
                SchemaDataClass::Metadata,
                "SHA-256 content digest",
                false,
            ),
            (
                "risk_flags",
                SchemaDataClass::Metadata,
                "Static metadata risk flags",
                false,
            ),
            (
                "raw_secret",
                SchemaDataClass::Secret,
                "Redacted secret fragment",
                true,
            ),
        ],
    ),
    (
        "findings",
        "Detections raised on risky tool calls, traversal, or unpinned MCP pins.",
        &[
            ("id", SchemaDataClass::Metadata, "Finding identifier", false),
            (
                "session_id",
                SchemaDataClass::Metadata,
                "Parent session identifier",
                false,
            ),
            (
                "severity",
                SchemaDataClass::Metadata,
                "Severity classification",
                false,
            ),
            (
                "lifecycle",
                SchemaDataClass::Metadata,
                "Finding triage state",
                false,
            ),
            (
                "title",
                SchemaDataClass::Metadata,
                "Short detection title",
                false,
            ),
            ("agent_name", SchemaDataClass::Metadata, "Agent name", false),
            (
                "user_id",
                SchemaDataClass::NamedIdentity,
                "Attributed org user ID",
                false,
            ),
            (
                "raw_secret",
                SchemaDataClass::Secret,
                "Matched credential payload",
                true,
            ),
        ],
    ),
];

pub fn catalog_entities() -> Vec<EntitySchema> {
    ENTITY_CATALOG
        .iter()
        .map(|(name, description, cols)| EntitySchema {
            name: (*name).into(),
            description: (*description).into(),
            columns: cols
                .iter()
                .map(|(cname, data_class, cdesc, sensitive)| ColumnDef {
                    name: (*cname).into(),
                    data_class: *data_class,
                    description: (*cdesc).into(),
                    sensitive: *sensitive,
                })
                .collect(),
        })
        .collect()
}
