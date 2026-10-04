"""End-to-end contract tests. All inputs are generated synthetic bytes."""

import gzip
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "vec_evidence.py"


class EvidenceCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"framework": "synthetic-only", "model": "none-called",
                                          "budget": {"usd": 0}, "permissions": {"network": False}}))
        self.prompt = self.root / "prompt.txt"
        self.prompt.write_text("Synthetic prompt. No biological data or model.\n")
        self.harness = self.root / "harness.py"
        self.harness.write_text("# Synthetic placeholder; never executed by this tool.\n")
        self.trace = self.root / "trace.jsonl"
        self.trace.write_bytes(('{"example_only":true,"observation":"가짜"}\n' * 75_000).encode())
        self.prediction = self.root / "prediction.synthetic.txt"
        self.prediction.write_bytes(b"not a competition prediction\n")
        self.lock = self.root / "run.lock.json"
        self.packet = self.root / "packet"

    def cli(self, *args, success=True):
        result = subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0 if success else 2, result.stdout + result.stderr)
        return json.loads(result.stdout if success else result.stderr)

    def do_lock(self, *extra):
        return self.cli("lock", "--config", self.config, "--prompt", self.prompt,
                        "--harness", self.harness, "--out", self.lock, *extra)

    def do_build(self, *extra, success=True, out=None):
        return self.cli("build", "--lock", self.lock, "--trajectory", self.trace,
                        "--prediction", self.prediction, "--out", out or self.packet,
                        "--already-uploaded-bytes", 0,
                        *extra, success=success)

    def complete_packet(self):
        self.do_lock()
        return self.do_build()

    def manifest(self):
        return json.loads((self.packet / "manifest.json").read_text())

    def write_manifest(self, manifest):
        (self.packet / "manifest.json").write_text(json.dumps(manifest))

    def test_lossless_large_round_trip_and_prediction_link(self):
        original = {p.name: p.read_bytes() for p in (self.config, self.prompt, self.harness,
                                                    self.trace, self.prediction)}
        self.complete_packet()
        self.assertEqual(gzip.decompress((self.packet / "trajectory.gz").read_bytes()), self.trace.read_bytes())
        report = self.cli("check", self.packet, "--prediction", self.prediction)
        self.assertTrue(report["prediction_bytes_verified"])
        self.assertEqual(report["official_autonomy_or_acceptance"], "not verified")
        self.assertEqual(report["package_bytes"], sum(p.stat().st_size for p in self.packet.rglob("*") if p.is_file()))
        self.assertEqual(original, {p.name: p.read_bytes() for p in (self.config, self.prompt,
                                                                    self.harness, self.trace, self.prediction)})
        self.assertNotIn(self.prediction.name, {p.name for p in self.packet.rglob("*")})
        self.assertNotIn(str(self.root), (self.packet / "lock.json").read_text())
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(self.packet.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.packet.rglob("*") if p.is_file()))

    def test_multiple_prompts_and_harness_files(self):
        second = self.root / "second.txt"
        second.write_text("Second synthetic prompt and harness artifact.\n")
        self.do_lock("--prompt", second, "--harness", second)
        self.do_build()
        files = self.manifest()["files"]
        self.assertEqual(sum(x["kind"] == "prompts" for x in files), 2)
        self.assertEqual(sum(x["kind"] == "harness" for x in files), 2)

    def test_changed_configuration_is_rejected_without_output(self):
        self.do_lock()
        self.config.write_text(self.config.read_text().replace('"usd": 0', '"usd": 1'))
        self.do_build(success=False)
        self.assertFalse(self.packet.exists())
        self.assertFalse(list(self.root.glob(".vec-evidence-*")))

    def test_changed_harness_is_rejected(self):
        self.do_lock()
        self.harness.write_text("# Modified after lock\n")
        self.do_build(success=False)
        self.assertFalse(self.packet.exists())

    def test_empty_trajectory_is_rejected(self):
        self.do_lock()
        self.trace.write_bytes(b"")
        self.do_build(success=False)

    def test_missing_evidence_is_rejected(self):
        self.complete_packet()
        self.prompt.unlink()
        (self.packet / "trajectory.gz").unlink()
        self.cli("check", self.packet, success=False)

    def test_bit_flip_is_rejected(self):
        self.complete_packet()
        file = self.packet / "harness" / "001-harness.py"
        file.write_bytes(file.read_bytes() + b"x")
        self.cli("check", self.packet, success=False)

    def test_rehashed_truncated_gzip_is_still_rejected(self):
        self.complete_packet()
        file = self.packet / "trajectory.gz"
        file.write_bytes(file.read_bytes()[:-5])
        manifest = self.manifest()
        for r in manifest["files"]:
            if r["kind"] == "trajectory":
                r["size_bytes"] = file.stat().st_size
                r["sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
        self.write_manifest(manifest)
        self.cli("check", self.packet, success=False)

    def test_manifest_cannot_rebind_a_changed_locked_file(self):
        self.complete_packet()
        file = self.packet / "harness" / "001-harness.py"
        file.write_text("# Different bytes\n")
        manifest = self.manifest()
        for r in manifest["files"]:
            if r["kind"] == "harness":
                r["size_bytes"] = file.stat().st_size
                r["sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
        self.write_manifest(manifest)
        self.cli("check", self.packet, success=False)

    def test_unsafe_manifest_path_is_rejected(self):
        self.complete_packet()
        manifest = self.manifest()
        manifest["files"][0]["path"] = "../config.json"
        self.write_manifest(manifest)
        self.cli("check", self.packet, success=False)

    def test_unlisted_file_is_rejected(self):
        self.complete_packet()
        (self.packet / "unlisted.txt").write_text("Extra bytes\n")
        self.cli("check", self.packet, success=False)

    def test_team_total_includes_previous_uploads(self):
        self.do_lock()
        self.do_build("--already-uploaded-bytes", 600_000_000, success=False)
        self.assertFalse(self.packet.exists())
        self.do_build("--already-uploaded-bytes", 123)
        report = self.cli("check", self.packet)
        self.assertEqual(report["team_bytes_after"], report["package_bytes"] + 123)

    def test_decimal_200_mb_file_boundary(self):
        with self.harness.open("wb") as file:
            file.seek(200_000_000)
            file.write(b"x")
        self.cli("lock", "--config", self.config, "--prompt", self.prompt,
                 "--harness", self.harness, "--out", self.lock, success=False)
        self.assertFalse(self.lock.exists())

    def test_expansion_limit_is_enforced_without_truncation(self):
        self.complete_packet()
        before = (self.packet / "trajectory.gz").read_bytes()
        self.cli("check", self.packet, "--max-expanded-bytes", 1, success=False)
        self.assertEqual(before, (self.packet / "trajectory.gz").read_bytes())

    def test_output_is_not_overwritten(self):
        self.complete_packet()
        before = (self.packet / "manifest.json").read_bytes()
        self.do_build(success=False)
        self.assertEqual(before, (self.packet / "manifest.json").read_bytes())
        self.cli("lock", "--config", self.config, "--prompt", self.prompt,
                 "--harness", self.harness, "--out", self.lock, success=False)

    def test_gzip_output_is_repeatable(self):
        self.complete_packet()
        other = self.root / "second-packet"
        self.do_build(out=other)
        self.assertEqual((self.packet / "trajectory.gz").read_bytes(), (other / "trajectory.gz").read_bytes())

    def test_credentials_and_duplicate_json_keys_are_rejected(self):
        for body in ('{"framework":"example","model":"none","api_key":"fake-key"}',
                     '{"framework":"example","framework":"second","model":"none"}',
                     '{"framework":"example","model":"none","budget":NaN}'):
            self.config.write_text(body)
            self.cli("lock", "--config", self.config, "--prompt", self.prompt,
                     "--harness", self.harness, "--out", self.lock, success=False)

    @unittest.skipIf(sys.platform == "win32", "Test requires POSIX symlinks")
    def test_symlink_inputs_are_rejected(self):
        link = self.root / "linked-prompt.txt"
        link.symlink_to(self.prompt)
        self.cli("lock", "--config", self.config, "--prompt", link,
                 "--harness", self.harness, "--out", self.lock, success=False)

    def test_changed_prediction_is_rejected_when_requested(self):
        self.complete_packet()
        self.prediction.write_text("Changed synthetic output\n")
        self.cli("check", self.packet, "--prediction", self.prediction, success=False)

    def test_framework_model_and_locked_kinds_cannot_be_dropped(self):
        self.complete_packet()
        original = self.manifest()
        for key in ("framework", "model"):
            changed = json.loads(json.dumps(original))
            changed[key] = ""
            self.write_manifest(changed)
            self.cli("check", self.packet, success=False)
        changed = json.loads(json.dumps(original))
        changed["files"] = [r for r in changed["files"] if r["kind"] != "prompts"]
        self.write_manifest(changed)
        self.cli("check", self.packet, success=False)


if __name__ == "__main__":
    unittest.main()
