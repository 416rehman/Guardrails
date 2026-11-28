# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Manifest, packaging, container, Helm, Terraform, and QA security tests for W5-2."""

import json
import pathlib
import plistlib
import re
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[2]
TEST_DIGEST = "sha256:1111111111111111111111111111111111111111111111111111111111111111"


class DeployManifestTests(unittest.TestCase):
    def test_daemon_manifests_reject_forbidden_protected_flags_and_align_permissions(self) -> None:
        systemd_daemon = (ROOT / "deploy/packaging/systemd/grdr-daemon.service").read_text("utf-8")
        exec_line = next(ln for ln in systemd_daemon.splitlines() if ln.startswith("ExecStart="))
        self.assertIn("--profile protected", exec_line)
        for bad in ("--data-dir", "--state-dir", "--bind", "--service"):
            self.assertNotIn(bad, exec_line)
        self.assertIn("User=root", systemd_daemon)
        self.assertIn("ConfigurationDirectoryMode=0750", systemd_daemon)
        self.assertIn("ReadWritePaths=/var/lib/guardrails /run/guardrails", systemd_daemon)

        decide_sock = (ROOT / "deploy/packaging/systemd/grdr-decide.socket").read_text("utf-8")
        local_sock = (ROOT / "deploy/packaging/systemd/grdr-local.socket").read_text("utf-8")
        self.assertIn("ListenStream=/run/guardrails/decide.sock", decide_sock)
        self.assertIn("SocketMode=0666", decide_sock)
        self.assertIn("SocketUser=root", decide_sock)
        self.assertIn("SocketGroup=root", decide_sock)
        self.assertIn("ListenStream=/run/guardrails/local.sock", local_sock)
        self.assertIn("SocketMode=0660", local_sock)
        self.assertIn("SocketGroup=grdr", local_sock)

        launchd_daemon = plistlib.loads(
            (ROOT / "deploy/packaging/launchd/com.guardrailshq.grdr.daemon.plist").read_bytes()
        )
        self.assertEqual(
            launchd_daemon["ProgramArguments"],
            ["/Library/Application Support/grdr/bin/grdr-daemon", "--profile", "protected"],
        )
        self.assertIn("decide", launchd_daemon["Sockets"])
        self.assertIn("local", launchd_daemon["Sockets"])

        win_svc = json.loads((ROOT / "deploy/packaging/windows/grdr-services.json").read_text("utf-8"))
        self.assertEqual(win_svc["data_dir"], r"C:\ProgramData\Guardrails\data")
        self.assertEqual(win_svc["pipes"]["decide"], r"\\.\pipe\grdr-protected-decide")
        self.assertEqual(win_svc["pipes"]["local"], r"\\.\pipe\grdr-protected-local")
        daemon_entry = next(s for s in win_svc["services"] if s["name"] == "grdr-daemon")
        self.assertEqual(daemon_entry["args"], ["--profile", "protected"])
        self.assertEqual(daemon_entry["account"], r"NT SERVICE\grdr-daemon")
        self.assertEqual(daemon_entry["sid_type"], "restricted")
        for worker in win_svc["child_workers"]:
            self.assertNotIn("--sandboxed", worker["args"])
            self.assertEqual(worker["sid_type"], "restricted")

    def test_server_manifests_isolate_dedicated_service_accounts(self) -> None:
        systemd_srv = (ROOT / "deploy/packaging/systemd/grdr-server.service").read_text("utf-8")
        self.assertIn("User=grdr-server", systemd_srv)
        self.assertIn("Group=grdr-server", systemd_srv)
        self.assertIn("EnvironmentFile=-/etc/grdr-server/server.env", systemd_srv)
        self.assertIn("ConfigurationDirectory=grdr-server", systemd_srv)
        self.assertIn("ConfigurationDirectoryMode=0750", systemd_srv)
        self.assertIn("--operator-bind 127.0.0.1:44444", systemd_srv)
        self.assertIn("--operator-web-dir /usr/share/grdr/operator-web", systemd_srv)

        launchd_srv = plistlib.loads(
            (ROOT / "deploy/packaging/launchd/com.guardrailshq.grdr.server.plist").read_bytes()
        )
        args = launchd_srv["ProgramArguments"]
        self.assertIn("--operator-bind", args)
        self.assertIn("127.0.0.1:44444", args)
        self.assertIn("--operator-web-dir", args)
        self.assertIn("/usr/local/share/grdr/operator-web", args)
        self.assertEqual(launchd_srv["StandardOutPath"], "/Library/Logs/grdr/server/server.log")

        macos_post = (ROOT / "deploy/packaging/macos-pkg/scripts/postinstall").read_text("utf-8")
        self.assertIn("refuse_if_symlink", macos_post)
        self.assertIn("_grdr-server", macos_post)

    def test_wix_and_nfpm_harden_binaries_acls_and_scripts(self) -> None:
        wxs_text = (ROOT / "deploy/packaging/wix/Package.wxs").read_text("utf-8")
        self.assertNotIn("LocalSystem", wxs_text)
        self.assertIn("ServerRdsh", wxs_text)
        self.assertIn(r"NT SERVICE\grdr-daemon", wxs_text)
        self.assertIn('Id="StateDir"', wxs_text)

        wxs_tree = ET.parse(ROOT / "deploy/packaging/wix/Package.wxs")
        ns = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
        svc_installs = wxs_tree.findall(".//w:ServiceInstall", ns)
        self.assertEqual(
            [el.attrib["Name"] for el in svc_installs],
            ["grdr-daemon", "grdr-engine", "grdr-uplink", "grdr-proxy"],
        )
        self.assertEqual(svc_installs[0].attrib["Arguments"], "--profile protected")
        self.assertEqual(svc_installs[0].attrib["Account"], r"NT SERVICE\grdr-daemon")

        wxs_sources = {el.attrib["Source"] for el in wxs_tree.findall(".//w:File", ns)}
        for exe in (
            r"$(var.BinDir)\grdr.exe",
            r"$(var.BinDir)\grdr-daemon.exe",
            r"$(var.BinDir)\grdr-engine.exe",
            r"$(var.BinDir)\grdr-uplink.exe",
            r"$(var.BinDir)\grdr-hook.exe",
            r"$(var.BinDir)\grdr-updater.exe",
            r"$(var.BinDir)\grdr-run.exe",
            r"$(var.BinDir)\grdr-mcp.exe",
            r"$(var.BinDir)\grdr-acp.exe",
            r"$(var.BinDir)\grdr-approve.exe",
            r"$(var.BinDir)\grdr-infer.exe",
            r"$(var.BinDir)\grdr-proxy.exe",
            r"$(var.BinDir)\grdr-tray.exe",
        ):
            self.assertIn(exe, wxs_sources)

        expected_bins = (
            "grdr",
            "grdr-daemon",
            "grdr-engine",
            "grdr-hook",
            "grdr-uplink",
            "grdr-updater",
            "grdr-proxy",
            "grdr-run",
            "grdr-mcp",
            "grdr-acp",
            "grdr-approve",
            "grdr-tray",
            "grdr-infer",
        )
        sys_grdr = (ROOT / "deploy/packaging/systemd/sysusers.d/grdr.conf").read_text("utf-8")
        self.assertIn("u grdr 65532", sys_grdr)
        self.assertIn("u grdr-engine", sys_grdr)
        self.assertNotIn("grdr-server", sys_grdr)

        sys_srv = (ROOT / "deploy/packaging/systemd/sysusers.d/grdr-server.conf").read_text("utf-8")
        self.assertIn("u grdr-server", sys_srv)
        self.assertNotIn("grdr-engine", sys_srv)

        for pkg in ("deb", "rpm"):
            nfpm_txt = (ROOT / f"deploy/packaging/{pkg}/nfpm.yaml").read_text("utf-8")
            for b in expected_bins:
                self.assertIn(f"${{GRDR_BIN_DIR}}/{b}", nfpm_txt)
            self.assertIn("/var/lib/guardrails", nfpm_txt)
            self.assertIn("owner: root", nfpm_txt)
            self.assertNotIn("owner: grdr", nfpm_txt)

            srv_txt = (ROOT / f"deploy/packaging/{pkg}/nfpm-server.yaml").read_text("utf-8")
            self.assertIn("${GRDR_BIN_DIR}/grdr-server", srv_txt)
            self.assertIn("sysusers.d/grdr-server.conf", srv_txt)
            self.assertNotIn("sysusers.d/grdr.conf", srv_txt)
            self.assertIn("/usr/share/grdr/operator-web", srv_txt)
            self.assertIn("/etc/grdr-server", srv_txt)
            self.assertIn("owner: grdr-server", srv_txt)
            self.assertIn("postinstall-server.sh", srv_txt)

            for script in ("postinstall.sh", "postinstall-server.sh"):
                post_txt = (ROOT / f"deploy/packaging/{pkg}/scripts/{script}").read_text("utf-8")
                self.assertNotIn("chown -R", post_txt)
                self.assertIn("if [ -L", post_txt)
            srv_post = (ROOT / f"deploy/packaging/{pkg}/scripts/postinstall-server.sh").read_text("utf-8")
            self.assertIn("/usr/lib/sysusers.d/grdr-server.conf", srv_post)
            self.assertNotIn("/usr/lib/sysusers.d/grdr.conf", srv_post)
            for script in ("preremove.sh", "preremove-server.sh"):
                pre_txt = (ROOT / f"deploy/packaging/{pkg}/scripts/{script}").read_text("utf-8")
                self.assertIn("|| true", pre_txt)

    def test_macos_mobileconfig_hardens_sysext_and_tcc_and_gates_vpn(self) -> None:
        raw_bytes = (
            ROOT / "deploy/packaging/macos-pkg/mobileconfig/com.guardrailshq.grdr.mobileconfig"
        ).read_bytes()
        raw_text = raw_bytes.decode("utf-8")
        self.assertNotIn("TEAMID0000", raw_text)
        self.assertNotIn("example.invalid", raw_text)

        profile = plistlib.loads(raw_bytes)
        payloads = profile["PayloadContent"]
        payload_types = {p["PayloadType"] for p in payloads}
        for req in (
            "com.guardrailshq.grdr",
            "com.apple.servicemanagement",
            "com.apple.system-extension-policy",
            "com.apple.webcontent-filter",
            "com.apple.TCC.configuration-profile-policy",
        ):
            self.assertIn(req, payload_types)
        self.assertNotIn("com.apple.dnsProxy.managed", payload_types)
        self.assertNotIn("com.apple.vpn.managed", payload_types)

        sysext = next(p for p in payloads if p["PayloadType"] == "com.apple.system-extension-policy")
        self.assertIs(sysext["AllowUserOverrides"], False)
        allowed_exts = sysext["AllowedSystemExtensions"]["__APPLE_TEAM_ID__"]
        self.assertEqual(
            allowed_exts,
            ["com.guardrailshq.grdr.esext", "com.guardrailshq.grdr.netext"],
        )

        wcf = next(p for p in payloads if p["PayloadType"] == "com.apple.webcontent-filter")
        self.assertEqual(wcf["FilterGrade"], "inspector")
        self.assertEqual(wcf["FilterDataProviderBundleIdentifier"], "com.guardrailshq.grdr.netext")

        tcc = next(p for p in payloads if p["PayloadType"] == "com.apple.TCC.configuration-profile-policy")
        for entries in tcc["Services"].values():
            for entry in entries:
                self.assertIn("CodeRequirement", entry)
                self.assertIn("__APPLE_TEAM_ID__", entry["CodeRequirement"])

        net_tpl = plistlib.loads(
            (
                ROOT
                / "deploy/packaging/macos-pkg/mobileconfig/com.guardrailshq.grdr.network-proxy.mobileconfig.template"
            ).read_bytes()
        )
        vpn = next(p for p in net_tpl["PayloadContent"] if p["PayloadType"] == "com.apple.vpn.managed")
        self.assertTrue(vpn["VendorConfig"]["TransparentProxy"])

    def test_containers_compose_and_helm_wire_isolation_and_hardening(self) -> None:
        cf_srv = (ROOT / "deploy/docker/Containerfile.server").read_text("utf-8")
        self.assertIn("COPY --from=web-builder /src/web/dist /rootfs/usr/share/grdr/web", cf_srv)
        self.assertIn(
            "COPY --from=web-builder /src/web/dist-operator /rootfs/usr/share/grdr/operator-web",
            cf_srv,
        )
        self.assertIn("--operator-bind", cf_srv)
        self.assertIn("--operator-web-dir", cf_srv)
        self.assertIn("/var/lib/grdr-objects", cf_srv)

        cf_sensor = (ROOT / "deploy/docker/Containerfile.node-sensor").read_text("utf-8")
        self.assertIn("-p grdr-uplink", cf_sensor)
        self.assertIn("-p grdr-updater", cf_sensor)
        self.assertIn("-p grdr-run", cf_sensor)
        self.assertIn("--chown=0:0 /rootfs/run/guardrails /run/guardrails", cf_sensor)
        self.assertIn('CMD ["--profile", "user"', cf_sensor)

        compose_ha = (ROOT / "deploy/compose/ha.yml").read_text("utf-8")
        self.assertIn("GRDR_OBJECT_STORE_DIR: /var/lib/grdr-objects", compose_ha)
        self.assertNotIn("GRDR_OBJECT_STORE_DIR: /var/lib/grdr/objects", compose_ha)
        self.assertIn('uid: "70"', compose_ha)
        self.assertIn('gid: "70"', compose_ha)
        self.assertIn("mode: 0400", compose_ha)
        self.assertIn("GRDR_OPERATOR_TOKEN: ${GRDR_OPERATOR_TOKEN:?", compose_ha)
        self.assertIn("grdr-server-1:", compose_ha)
        self.assertGreaterEqual(compose_ha.count("healthcheck:"), 4)

        for chart_np in (
            "deploy/helm/grdr-server/templates/networkpolicy.yaml",
            "deploy/helm/grdr-node-sensor/templates/networkpolicy.yaml",
        ):
            self.assertNotIn("169.0.0.0/8", (ROOT / chart_np).read_text("utf-8"))

        helm_bin = shutil.which("helm")
        if helm_bin is None:
            self.skipTest("helm CLI not available")

        srv_rendered = subprocess.check_output(
            [
                helm_bin,
                "template",
                "w5",
                "deploy/helm/grdr-server",
                "--set",
                f"image.digest={TEST_DIGEST}",
                "--set",
                "operator.existingSecret=op-sec",
                "--set",
                "storage.database.existingSecret=db-sec",
                "--set",
                "storage.objectStore.endpoint=https://s3.example.invalid",
                "--set",
                "storage.objectStore.bucket=grdr-data",
                "--set",
                "storage.objectStore.backupBucket=grdr-backup",
                "--set",
                "storage.objectStore.pathStyle=true",
            ],
            cwd=ROOT,
            text=True,
        )
        self.assertIn("--operator-bind", srv_rendered)
        self.assertIn("0.0.0.0:44444", srv_rendered)
        self.assertIn("--operator-web-dir", srv_rendered)
        self.assertIn("/usr/share/grdr/operator-web", srv_rendered)
        self.assertIn("--strict", srv_rendered)
        self.assertIn("--check-pg-clock", srv_rendered)
        self.assertIn("/var/lib/grdr-objects", srv_rendered)
        self.assertIn("GRDR_OPERATOR_TOKEN", srv_rendered)
        self.assertIn("name: w5-grdr-server-metrics", srv_rendered)
        self.assertIn("port: 9090", srv_rendered)
        self.assertIn("--object-store-path-style", srv_rendered)

        sensor_rendered = subprocess.check_output(
            [
                helm_bin,
                "template",
                "ns",
                "deploy/helm/grdr-node-sensor",
                "--set",
                f"image.digest={TEST_DIGEST}",
                "--set",
                "mode=hybrid",
                "--set",
                "sidecar.enabled=true",
                "--set",
                "server.endpoint=https://grdr.example.invalid:8443",
            ],
            cwd=ROOT,
            text=True,
        )
        daemon_block = sensor_rendered.split("kind: DaemonSet", 1)[1]
        self.assertNotIn("--data-dir", daemon_block.split("volumes:", 1)[0])
        self.assertNotIn("sensor.toml", daemon_block)
        self.assertIn("mountPath: /var/lib/guardrails", daemon_block)
        self.assertIn("mountPath: /run/guardrails", daemon_block)
        self.assertIn("/var/lib/guardrails/run", sensor_rendered)
        self.assertIn("GRDR_SERVER_URL", sensor_rendered)

    def test_terraform_modules_enforce_d70_wif_and_tls(self) -> None:
        for cloud in ("aws", "azure", "gcp"):
            main_txt = (ROOT / f"deploy/terraform/{cloud}/main.tf").read_text("utf-8")
            vars_txt = (ROOT / f"deploy/terraform/{cloud}/variables.tf").read_text("utf-8")
            test_txt = (ROOT / f"deploy/terraform/{cloud}/tests/module.tftest.hcl").read_text("utf-8")
            self.assertEqual(main_txt.count("{"), main_txt.count("}"))
            self.assertEqual(vars_txt.count("{"), vars_txt.count("}"))
            self.assertEqual(test_txt.count("{"), test_txt.count("}"))
            self.assertIn("operator_existing_secret", vars_txt)
            self.assertIn("existingSecret = var.operator_existing_secret", main_txt)
            self.assertIn('dir            = "/var/lib/grdr-objects"', main_txt)
            self.assertIn("trimsuffix(lower(trimspace(", main_txt)
            self.assertIn("precondition", main_txt)
            self.assertIn("reject_same_operator_host_d70", test_txt)
            self.assertIn("reject_case_normalized_operator_host_d70", test_txt)

        aws_main = (ROOT / "deploy/terraform/aws/main.tf").read_text("utf-8")
        self.assertIn("aws:SourceAccount", aws_main)
        self.assertIn("aws:SourceArn", aws_main)
        self.assertIn("aws:SecureTransport", aws_main)

        azure_main = (ROOT / "deploy/terraform/azure/main.tf").read_text("utf-8")
        self.assertEqual(azure_main.count("Storage Blob Data Contributor"), 2)

        gcp_main = (ROOT / "deploy/terraform/gcp/main.tf").read_text("utf-8")
        self.assertIn(".svc.id.goog[${var.kubernetes_namespace}/${var.service_account_name}]", gcp_main)
        self.assertIn("roles/storage.objectViewer", gcp_main)

    def test_qa_scripts_have_no_removed_flags_or_insecure_defaults(self) -> None:
        qa_files = (
            "deploy/qa/run-slice0-e2e.sh",
            "deploy/qa/run_slice0_lab.py",
            "deploy/qa/vm/linux-guest-e2e.sh",
            "deploy/qa/vm/win-guest-e2e.ps1",
        )
        removed_patterns = (
            r"--interval-secs",
            r"--floor-table",
            r"--floor-key",
            r"--device-name",
            r"/local/v1/status",
            r"grdr-hook[^\n]*--daemon",
        )
        for rel in qa_files:
            txt = (ROOT / rel).read_text("utf-8")
            for pat in removed_patterns:
                self.assertIsNone(re.search(pat, txt), f"{rel} still matches {pat}")
            self.assertIn("--decide-endpoint", txt)
            self.assertIn("--local-endpoint", txt)

        qa_compose = (ROOT / "deploy/qa/docker-compose.yml").read_text("utf-8")
        self.assertNotIn("-dev", qa_compose)
        self.assertNotIn("/tmp/grdr-qa-decide.sock", qa_compose)

        qa_dockerfile = (ROOT / "deploy/qa/Dockerfile").read_text("utf-8")
        self.assertIn("--ignore-scripts", qa_dockerfile)
        self.assertIn("@sha256:", qa_dockerfile)
        self.assertEqual(qa_dockerfile.count("USER "), 3)

        slice0_sh = (ROOT / "deploy/qa/run-slice0-e2e.sh").read_text("utf-8")
        self.assertNotIn("/tmp/grdr-qa-decide.sock", slice0_sh)
        self.assertNotIn("/tmp/grdr-missing-decide.sock", slice0_sh)

        linux_e2e = (ROOT / "deploy/qa/vm/linux-guest-e2e.sh").read_text("utf-8")
        self.assertNotIn("urlopen('${SERVER_URL}", linux_e2e)
        self.assertIn("is_shared_tmp_path", linux_e2e)
        self.assertNotIn("${TMPDIR:-/tmp}", linux_e2e)
        self.assertIn("mktemp -d", linux_e2e)

        lab_py = (ROOT / "deploy/qa/run_slice0_lab.py").read_text("utf-8")
        self.assertIn("--ignore-scripts", lab_py)
        self.assertIn("_safe_lab_parent", lab_py)
        self.assertNotIn("TemporaryDirectory()", lab_py)

        wsl_ps1 = (ROOT / "deploy/qa/vm/wsl-e2e.ps1").read_text("utf-8")
        self.assertNotIn("/tmp/grdr-wsl", wsl_ps1)

        vmware_ps1 = (ROOT / "deploy/qa/vm/vmware-e2e.ps1").read_text("utf-8")
        self.assertNotIn('"-vp"', vmware_ps1)
        self.assertNotIn('"-gp"', vmware_ps1)
        self.assertNotIn("Windows/Temp", vmware_ps1)
        self.assertNotIn(r"Windows\Temp", vmware_ps1)
        self.assertNotIn("/tmp/grdr-wsl-cargo-target", vmware_ps1)
        self.assertIn("ReparsePoint", vmware_ps1)

        smoke_py = (ROOT / "deploy/qa/smoke_cell.py").read_text("utf-8")
        self.assertIn("--decide-endpoint", smoke_py)
        self.assertIn("--state-dir", smoke_py)
        self.assertIn("fail_closed_res.returncode != 2", smoke_py)

        helm_bin = shutil.which("helm")
        if helm_bin is not None:
            bad_ipv6_supernets = (
                "::1/128",
                "::0:1/128",
                "fd00::/8",
                "fd00::/16",
                "fd00:e00::/24",
                "fd00:ec0::/30",
                "fe00::/8",
                "::fffe:0:0/95",
                "0:0:0:0:0:fffe:0:0/95",
                "0:0:0:0:0:8000:0:0/81",
            )
            for chart in ("grdr-server", "grdr-node-sensor"):
                extra = (
                    ["--set", "operator.existingSecret=op-sec", "--set", "storage.database.existingSecret=db-sec"]
                    if chart == "grdr-server"
                    else []
                )
                for bad in bad_ipv6_supernets:
                    res = subprocess.run(
                        [
                            helm_bin,
                            "template",
                            "t",
                            f"deploy/helm/{chart}",
                            "--set",
                            f"image.digest={TEST_DIGEST}",
                            *extra,
                            "--set",
                            f"networkPolicy.allowEgressCidrs={{{bad}}}",
                        ],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(res.returncode, 0, f"{chart} unexpectedly allowed {bad}")
                ok_res = subprocess.run(
                    [
                        helm_bin,
                        "template",
                        "t",
                        f"deploy/helm/{chart}",
                        "--set",
                        f"image.digest={TEST_DIGEST}",
                        *extra,
                        "--set",
                        "networkPolicy.allowEgressCidrs={10.0.0.0/8,2001:db8::/32,fd12:3456::/48,fd00:1234::/48}",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(ok_res.returncode, 0, f"{chart} rejected valid CIDRs: {ok_res.stderr}")

        win_ps1 = (ROOT / "deploy/qa/vm/win-guest-e2e.ps1").read_text("utf-8")
        self.assertIn("$1$1", win_ps1)


if __name__ == "__main__":
    unittest.main()
