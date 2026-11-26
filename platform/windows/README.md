# Windows Native Kernel & Host Components (`platform/windows/`)

This directory contains the buildable C/WDK and Win32 native component sources matching `crates/grdr-sensor-windows`:

- `grdr-driver/`: Optional WDK kernel-mode minifilter, WFP connect-redirect callout, and `PsSetCreateProcessNotifyRoutineEx2` process callback (`GRDRWM01` wire header matching `driver_seam.rs`, 50 ms bounded floor-table deadline, SYSTEM-only `FltCreateCommunicationPort`, 2-bugcheck boot-loop disable guard).
- `grdr-wsl/`: `grdr-wsl.dll` implementing `WSLPluginHooksV1` (`OnVMStarted`, `OnDistributionStarted`, `OnDistributionStopping`) with non-blocking callbacks and single-use enrollment token delivery to `grdr-wsl-guest` via stdin (never argv), failing open so WSL distros still boot on sensor fault.
- `grdr-amsi/`: Opt-in `grdr-amsi.dll` `IAntimalwareProvider` COM DLL with shared-memory lineage bitmap early-out (non-agent processes exit immediately), 50 ms fail-open named-pipe forward to `grdr-engine`, and 3-crash auto-unregister circuit breaker.

## External Blockers (`[EXT]`)

- `[EXT]` **WDK + EV Code Signing & WHCP Submission (`grdr-driver`):** Compiling and loading `grdr-driver.sys` on production Windows requires Microsoft Enterprise WDK (`wdk-km`), an EV Authenticode hardware/cloud HSM signing certificate, MVI partner altitude allocation (`320000..329999` or Guardrails-assigned altitude), and Hardware Lab Kit (`HLK`) + Driver Verifier 72h certification via Microsoft Partner Center (`WHCP`) before HVCI/Secure Boot systems will load the driver.
- `[EXT]` **Authenticode EV Signing (`grdr-wsl.dll`, `grdr-amsi.dll`):** Unsigned DLLs load in test-mode/dev builds only; Windows App Control / Smart App Control / WDAC policies require organization Authenticode signing before fleet deployment.

## Local Build Instructions (Windows MSVC + WDK)

1. Configure DLL targets (`grdr-wsl.dll` and `grdr-amsi.dll`) from a Visual Studio Developer Prompt:
   ```powershell
   cmake -S platform/windows -B build-win-native -G "Visual Studio 17 2022" -A x64
   cmake --build build-win-native --config Release
   ```
2. Build `grdr-driver.sys` inside an Enterprise WDK / VS + WDK environment (`-DGRDR_BUILD_KMDF_DRIVER=ON` with `%WDKContentRoot%` configured).
