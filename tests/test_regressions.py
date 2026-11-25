"""Regression tests for bugs, security boundaries, data leaks, and edge cases."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_engine import Fixture
import _audit as audit
import _cli as cli
import _core as core
import _native as native
import _remove as removal


class RegressionTests(Fixture):
    def test_windows_system_parts_anchored_at_drive_root(self):
        with patch.object(core, "platform_id", return_value="windows"):
            wer = self.root / "AppData/Local/Microsoft/Windows/WER/report.wer"
            wer.parent.mkdir(parents=True)
            wer.write_bytes(b"wer")
            rule = next(r for r in core.read_rules() if r["id"] == "windows-error-reports")
            if os.name == "nt":
                self.assertFalse(core.protected(wer))
                matched, kind, _ = core.classify(wer, self.root, core.identity(wer.stat()), [rule])
                self.assertEqual(kind, "REVIEW")
                self.assertEqual(matched["id"], "windows-error-reports")
                self.assertTrue(core.protected(Path("C:\\Windows\\System32\\cmd.exe")))
                self.assertTrue(core.protected(Path("C:\\ProgramData\\secret.dat")))
                self.assertTrue(core.protected(Path("C:\\Program Files\\app\\a.bin")))

    def test_scan_rejects_empty_roots_exclusions_and_bool_budgets(self):
        for bad in (
            {"roots": [""]},
            {"roots": ["   "]},
            {"roots": [str(self.root)], "exclude": [""]},
            {"roots": [str(self.root)], "exclude": ["  "]},
            {"roots": [str(self.root)], "max_entries": True},
            {"roots": [str(self.root)], "max_depth": False},
            {"roots": [str(self.root)], "max_seconds": True},
        ):
            with self.subTest(bad=bad), self.assertRaises(core.Refusal):
                core.scan(bad)

    def test_analyze_clamps_negative_top_and_rejects_bool_top(self):
        (self.root / "extra.bin").write_bytes(b"extra")
        inv = self.inventory()
        res = core.analyze({"inventory": inv, "top": -1})
        self.assertEqual(len(res["largest"]), 1)
        with self.assertRaises(core.Refusal):
            core.analyze({"inventory": inv, "top": True})

    def test_human_report_unknown_disk_line_not_merged_with_table_header(self):
        with patch.object(core.shutil, "disk_usage", side_effect=PermissionError("denied")):
            inv = self.inventory()
        md = core.human_report({"inventory": inv})["markdown"]
        lines = md.splitlines()
        disk_idx = next(i for i, line in enumerate(lines) if line.startswith("Disk space: unknown"))
        self.assertEqual(lines[disk_idx + 1], "")
        self.assertTrue(lines[disk_idx + 2].startswith("| Classification |"))

    def test_zero_inode_files_counted_independently(self):
        (self.root / "a.bin").write_bytes(b"12345")
        (self.root / "b.bin").write_bytes(b"67890")
        inv = self.inventory()
        for e in inv["entries"]:
            e["identity"]["inode"] = 0
            e["unique_inode"] = True
        summary = core.summarize(inv["entries"])
        self.assertEqual(summary["PROTECTED"]["logical_bytes"], sum(e["logical_bytes"] for e in inv["entries"] if e["classification"] == "PROTECTED"))
        totals = audit.directory_totals(inv)
        root_row = next(r for r in totals if r["path"] == str(self.root))
        self.assertEqual(root_row["files"], len(inv["entries"]))

    def test_cli_cell_escapes_markdown_and_html(self):
        rendered = cli.cell("![img](https://evil.invalid)<script>|a\nb\rc")
        self.assertNotIn("![", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("\n", rendered)
        self.assertNotIn("\r", rendered)
        self.assertIn("\\|", rendered)
        self.assertEqual(cli.cell("root 1/example.py"), "root 1/example.py")

    def test_preserve_offline_protects_dependency_store_and_relative_exclusions(self):
        store_file = self.root / ".pnpm-store/v3/pkg.bin"
        store_file.parent.mkdir(parents=True)
        store_file.write_bytes(b"pkg")
        self.own(self.root, recursive=True)
        inv = self.inventory()
        entry = next(e for e in inv["entries"] if e["path"] == str(store_file))
        self.assertEqual(entry["category"], "dependency-store")
        with self.assertRaises(core.Refusal):
            removal.create_plan({"inventory": inv, "candidate_ids": [entry["id"]], "policy": {"preserve_offline": True}})
        bc = self.candidate(inv)
        dotdot_exc = os.path.join(str(self.bytecode.parent), "nested", "..")
        with self.assertRaises(core.Refusal):
            removal.create_plan({"inventory": inv, "candidate_ids": [bc["id"]], "policy": {"exclude": [dotdot_exc]}})
        with patch.object(Path, "home", return_value=self.root), patch.dict(os.environ, {"HOME": str(self.root), "USERPROFILE": str(self.root)}):
            with self.assertRaises(core.Refusal):
                removal.create_plan({"inventory": inv, "candidate_ids": [bc["id"]], "policy": {"exclude": ["~/__pycache__"]}})

    def test_project_markers_protected_even_with_include_personal(self):
        self.own(self.root, recursive=True)
        for name in ("pom.xml", "build.gradle", "tsconfig.json"):
            p = self.root / name
            p.write_text("{}")
            self.own(p)
        inv = self.inventory()
        for name in ("pom.xml", "build.gradle", "tsconfig.json"):
            entry = next(e for e in inv["entries"] if e["path"] == str(self.root / name))
            with self.subTest(name=name), self.assertRaises(core.Refusal):
                removal.create_plan({"inventory": inv, "candidate_ids": [entry["id"]], "include_personal": True})

    @unittest.skipUnless(core.removal_supported(), "Exact removal handles unavailable")
    def test_verify_rejects_forged_plan_id_and_operations_handles_many_attempts(self):
        self.own(self.root, recursive=True)
        inv = self.inventory()
        bc = self.candidate(inv)
        plan = removal.create_plan({"inventory": inv, "candidate_ids": [bc["id"]]})
        res = removal.execute({
            "state_dir": str(self.state), "plan": plan, "plan_digest": plan["digest"],
            "candidate_ids": [bc["id"]], "user_approved": True, "acknowledge_irreversible": True,
        })
        for i in range(2100):
            (self.state / f"remove-attempt-{res['id']}-{i:024x}.json").write_text("{}")
        ops = removal.operations({"state_dir": str(self.state)})
        self.assertEqual([o["id"] for o in ops["operations"]], [res["id"]])
        result_file = self.state / f"remove-result-{res['id']}.json"
        tampered = json.loads(result_file.read_text())
        tampered["plan_id"] = "../escape"
        result_file.write_text(json.dumps(tampered))
        with self.assertRaises(core.Refusal):
            removal.verify({"state_dir": str(self.state), "operation_id": res["id"]})

    def test_native_normalization_and_validation(self):
        with patch.object(core, "platform_id", return_value="windows"), patch.object(
            native, "read_command", return_value={"status": "ok", "complete": True, "metadata": json.dumps([{"name": "Tool", "version": None}])}
        ):
            apps = native.applications({"authorized": True})
            self.assertEqual(apps["applications"][0]["version"], "unknown")
        inv = self.inventory()
        bc = self.candidate(inv)
        with self.assertRaises(core.Refusal):
            native.activity({"authorized": True, "inventory": inv, "candidate_ids": [bc["id"], bc["id"]]})
        if os.name == "nt":
            with self.assertRaises(core.Refusal):
                native.recycle_bin({"authorized": True, "volumes": ["\u03b1:\\"]})

    def test_leftovers_token_boundary_matching(self):
        bun = self.root / ".bun/install/cache/pkg.tgz"
        bun.parent.mkdir(parents=True)
        bun.write_bytes(b"bun")
        edge = self.root / "Microsoft/Edge/User Data/Default/Cache/data"
        edge.parent.mkdir(parents=True)
        edge.write_bytes(b"edge")
        inv = self.inventory()
        apps = {"source": "native-installed-applications", "complete": True,
                "applications": [{"name": "ubuntu-base", "id": "ubuntu-base"}, {"name": "knowledge-app", "id": "knowledge-app"}, {"name": "python3.12", "id": "python3.12"}]}
        res = audit.leftovers({"inventory": inv, "applications": apps})["associations"]
        by_app = {r["application"]: r["association"] for r in res}
        self.assertEqual(by_app.get("Bun"), "not-observed-in-native-inventory")
        self.assertEqual(by_app.get("Chromium family"), "not-observed-in-native-inventory")
        self.assertEqual(by_app.get("CPython"), "present-in-native-inventory")

    def test_probe_expands_tilde_path(self):
        with patch.object(Path, "home", return_value=self.root):
            res = core.probe({"path": "~"})
        self.assertEqual(res["disk"]["status"], "available")

    def test_canonical_rejects_nan(self):
        with self.assertRaises(ValueError):
            core.canonical({"bad": float("nan")})

    def test_cli_output_not_corrupted_if_stdout_fails(self):
        out = self.base / "out.json"
        with patch("builtins.print", side_effect=[UnicodeEncodeError("cp1252", "x", 0, 1, "unencodable"), None]):
            code = cli.main(["doctor", "--path", str(self.root), "--output", str(out), "--json"])
        self.assertEqual(code, 2)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(payload["ok"])

    @unittest.skipUnless(os.name == "posix", "POSIX FIFOs and safe_hash")
    def test_safe_hash_refuses_non_regular_file(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        entry = {"path": str(fifo), "root": str(self.root), "identity": core.identity(fifo.lstat())}
        with self.assertRaises(core.Refusal):
            core.safe_hash(entry, 1024)

    def test_markdown_cells_keep_quotes_readable(self):
        self.assertEqual(cli.cell("it's \"x\""), "it's \"x\"")
        self.assertEqual(cli.cell("a<b>#"), "a&lt;b&gt;\\#")
        self.assertNotIn("&#x27;", cli.cell("'"))

    def test_scan_budgets_reject_non_numeric_types_as_refusal(self):
        for bad in ({"max_entries": "many"}, {"max_depth": [1]}, {"max_seconds": "10"}):
            with self.subTest(bad=bad), self.assertRaises(core.Refusal):
                core.scan({"roots": [str(self.root)], **bad})

    def test_profile_budget_rejects_non_numeric_override(self):
        request = {"roots": [str(self.root)], "max_entries": "many", "policy": {"max_entries": 10}}
        with self.assertRaises(core.Refusal):
            audit.resolve_scope(request)

    def test_run_bounded_kills_child_when_monitoring_fails(self):
        with patch.object(core.os, "fstat", side_effect=OSError("boom")):
            code, data, truncated, timed_out = core.run_bounded(
                [sys.executable, "-c", "import time; time.sleep(30)"], timeout=5)
        self.assertIsNone(code)
        self.assertEqual((data, truncated, timed_out), (b"", False, False))


if __name__ == "__main__":
    unittest.main()
