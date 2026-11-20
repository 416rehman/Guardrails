// AC-5 of #1550: 1000 sequential subprocess runs of gate-paths.mjs against the reference model,
// each inside the timeout registered in .claude/settings.json.
import assert from "node:assert/strict";
import { test } from "node:test";
import { GRANT_2, GRANT_5, makeRepository, realHookTimeoutMs, runHook } from "./fixture.mjs";
import { generateCase, rng, writeSetPredicate } from "./model.mjs";

const RUNS = 1000;

test("soak: 1000 hook runs match the reference model inside the registered timeout", () => {
  const timeoutMs = realHookTimeoutMs();
  assert.ok(timeoutMs > 0, "gate-paths.mjs has no timeout registered in .claude/settings.json");
  const repo = makeRepository();
  try {
    const world = {
      windows: process.platform === "win32",
      roots: Object.fromEntries(Object.entries(repo.roots).map(([name, path]) => [name, path.replaceAll("\\", "/")])),
      outside: repo.outside.replaceAll("\\", "/"),
      grants: {
        w2: { agent: GRANT_2.agent, inWriteSet: writeSetPredicate(GRANT_2.write_set) },
        w4: "invalid",
        w5: { agent: GRANT_5.agent, inWriteSet: writeSetPredicate(GRANT_5.write_set) },
      },
    };
    const seed = Number(process.env.GRDR_GATE_SEED ?? Date.now() % 2 ** 31);
    console.log(`soak seed ${seed}`);
    const random = rng(seed);
    const failures = [];
    let slowest = 0;
    for (let i = 0; i < RUNS; i += 1) {
      const { input, expected } = generateCase(random, world);
      const result = runHook(repo.main, input);
      slowest = Math.max(slowest, result.ms);
      if (result.code !== expected || result.ms >= timeoutMs) failures.push({ expected, actual: result.code, ms: result.ms, input });
    }
    console.log(`soak slowest run ${Math.round(slowest)} ms of ${timeoutMs} ms`);
    assert.deepEqual(failures.slice(0, 5), [], `seed ${seed}: ${failures.length} failures`);
  } finally {
    repo.remove();
  }
});
