// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// The entry point of the branch check; the checks live in branch-findings.mjs. It has no main-module
// test on purpose: through a symlink or junction such a test is false and the check exits 0 unseen.
import { main } from "./branch-findings.mjs";

process.exitCode = main(process.argv.slice(2));
