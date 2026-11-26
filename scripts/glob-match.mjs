// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Linear-time glob matcher supporting **, **/, /**, *, and ? without dynamic RegExp compilation.

export function compileGlob(glob) {
  const tokens = [];
  let i = 0;
  while (i < glob.length) {
    const rest = glob.slice(i);
    if (rest === "**") {
      tokens.push({ kind: "any" });
      i += 2;
    } else if (rest.startsWith("**/")) {
      tokens.push({ kind: "slashAnyPrefix" });
      i += 3;
    } else if (rest.startsWith("/**")) {
      tokens.push({ kind: "slashAnySuffix" });
      i += 3;
    } else if (glob[i] === "*") {
      tokens.push({ kind: "segStar" });
      i += 1;
    } else if (glob[i] === "?") {
      tokens.push({ kind: "segQ" });
      i += 1;
    } else {
      tokens.push({ kind: "lit", ch: glob[i] });
      i += 1;
    }
  }
  return { test: (target) => matchGlobTokens(tokens, target) };
}

function matchGlobTokens(tokens, target) {
  const n = target.length;
  let dp = new Uint8Array(n + 1);
  dp[0] = 1;
  for (const tok of tokens) {
    const next = new Uint8Array(n + 1);
    if (tok.kind === "lit") {
      for (let s = 0; s < n; s += 1) {
        if (dp[s] && target[s] === tok.ch) next[s + 1] = 1;
      }
    } else if (tok.kind === "segQ") {
      for (let s = 0; s < n; s += 1) {
        if (dp[s] && target[s] !== "/") next[s + 1] = 1;
      }
    } else if (tok.kind === "segStar") {
      for (let s = 0; s <= n; s += 1) {
        if (dp[s]) next[s] = 1;
        if (s < n && next[s] && target[s] !== "/") next[s + 1] = 1;
      }
    } else if (tok.kind === "any") {
      let seen = false;
      for (let s = 0; s <= n; s += 1) {
        if (dp[s]) seen = true;
        if (seen) next[s] = 1;
      }
    } else if (tok.kind === "slashAnyPrefix") {
      let seen = false;
      for (let s = 0; s <= n; s += 1) {
        if (dp[s]) {
          next[s] = 1;
          seen = true;
        }
        if (seen && s > 0 && target[s - 1] === "/") next[s] = 1;
      }
    } else if (tok.kind === "slashAnySuffix") {
      let fillAll = false;
      for (let s = 0; s <= n; s += 1) {
        if (dp[s]) {
          next[s] = 1;
          if (s < n && target[s] === "/") fillAll = true;
        }
        if (fillAll) next[s] = 1;
      }
    }
    dp = next;
  }
  return dp[n] === 1;
}
