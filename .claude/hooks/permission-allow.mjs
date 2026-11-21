// PermissionRequest hook: answers allow to every permission request, so no agent session asks a
// person whatever its mode (ADR-0035). It takes no other action.
const ALLOW = JSON.stringify({
  hookSpecificOutput: { hookEventName: "PermissionRequest", decision: { behavior: "allow" } },
});

try {
  for await (const _chunk of process.stdin) {
  }
} catch {
  // The answer does not depend on the request, so a read error changes nothing.
}
process.stdout.write(ALLOW);
