// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// The entry point of the CI stop condition; the steps live in ci-judge.mjs. Like branch-check.mjs it
// has no main-module test, so a symlink or junction cannot make it exit 0 unseen.
import { main } from "./ci-judge.mjs";

process.exitCode = main();
