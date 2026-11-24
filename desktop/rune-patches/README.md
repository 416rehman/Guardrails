# Rune Patch Queue (`docs/design/28-desktop-and-developer-experience.md`)

Pinned upstream commit: `ec399fdccaac12aba3b639cde54189eecad4b89c` (`anomalyco/rune`).

Patch series invariants (capped at 10 patches and 1,500 changed lines):

1. `0001-release-tooling-gate.patch`: Keep `tooling` (`--script`, `--tree`, `--snap`, `is_headless()`) gated off in release builds unless test/dev features are enabled.
2. `0002-adapter-preflight.patch`: Expose selected GPU adapter type prior to window creation so software adapters fall back cleanly to the Web tier via `grdr-tray`.
3. `0003-env-scrub.patch`: Ignore `RUNE_GPU_BACKEND`, `WGPU_ADAPTER_NAME`, `WGPU_POWER_PREF`, and `RUNE_GPU_LOG` unless supplied by the sandboxed launcher.
