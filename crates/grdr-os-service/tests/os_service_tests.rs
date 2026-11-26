// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::error::Error;

use grdr_os_service::unix_control::{
    install_signal_handlers, request_reload, request_shutdown, send_systemd_notify,
    shutdown_requested, take_reload_requested,
};
use grdr_os_service::win_scm::{
    ScmState, demand_start_service, query_service_process, register_scm_handler, report_scm_state,
};
use grdr_os_service::{
    ServiceAdapter, ServiceError, ServiceManagerBackend, ServiceManagerState, SystemServiceAdapter,
};

#[test]
fn signal_reload_and_shutdown_flags_roundtrip_without_blocking() {
    let res = run_signal_flags();
    assert!(res.is_ok(), "{res:?}");
}

fn run_signal_flags() -> Result<(), Box<dyn Error>> {
    install_signal_handlers()?;
    let _ = take_reload_requested();
    request_reload();
    if !take_reload_requested() || take_reload_requested() {
        return Err("take_reload_requested state mismatch".into());
    }
    if !shutdown_requested() {
        request_shutdown();
        if !shutdown_requested() {
            return Err("shutdown_requested did not reflect request".into());
        }
    }
    Ok(())
}

#[test]
fn scm_probe_rejects_invalid_service_names_and_handles_missing_cleanly() {
    let res = run_scm_probe();
    assert!(res.is_ok(), "{res:?}");
}

fn run_scm_probe() -> Result<(), Box<dyn Error>> {
    for bad in ["", "   ", "svc\0evil", r"svc\evil"] {
        if !matches!(
            query_service_process(bad),
            Err(ServiceError::NotifyFailed(_))
        ) {
            return Err(format!("expected NotifyFailed for invalid service name `{bad:?}`").into());
        }
        if !matches!(
            register_scm_handler(bad),
            Err(ServiceError::NotifyFailed(_))
        ) {
            return Err(format!("expected register_scm_handler fail for `{bad:?}`").into());
        }
    }

    let probe = query_service_process("GuardrailsNonExistentServiceForUnitTest")?;
    if probe.is_some() {
        return Err("missing SCM service should yield None".into());
    }
    if demand_start_service("GuardrailsNonExistentServiceForUnitTest", 50).is_ok() {
        return Err("demand_start_service on missing service must fail".into());
    }
    report_scm_state(ScmState::Running, 0)?;

    let adapter = SystemServiceAdapter::with_backend(ServiceManagerBackend::WindowsScm);
    adapter.report_state(&ServiceManagerState::Ready)?;

    #[cfg(unix)]
    {
        for bad_sock in ["", "relative.sock", "@", "/tmp/\0bad"] {
            if send_systemd_notify(bad_sock, "READY=1\n").is_ok() {
                return Err(format!("expected notify rejection for `{bad_sock:?}`").into());
            }
        }
    }
    #[cfg(not(unix))]
    {
        send_systemd_notify("", "READY=1\n")?;
    }
    Ok(())
}
