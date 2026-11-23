#!/usr/bin/env python3
"""Unit tests for the Toob-Loader Attack-Corpus schema, anti-tampering & scoring."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import judge_runner as jr  # noqa: E402


class TestAttackCorpusJudge(unittest.TestCase):
    def test_all_seed_bundles_validate_cleanly(self) -> None:
        corpus_dir = Path(__file__).resolve().parent
        bundles = jr.discover_bundles(corpus_dir)
        self.assertGreaterEqual(len(bundles), 6)
        for bdir in bundles:
            bundle = jr.load_and_validate_bundle(bdir)
            self.assertEqual(bundle.meta["expected_outcome"], "defended")

    def test_rejects_forbidden_payload_extension(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bdir = Path(td) / "ATK-9999-nrf52840-runtime-evil"
            (bdir / "payload").mkdir(parents=True)
            (bdir / "attack.toml").write_text(
                "\n".join([
                    'id = "ATK-9999"',
                    'title = "Forbidden Renode Script"',
                    'team = "team-2"',
                    'chip = "nrf52840"',
                    'phase = "runtime"',
                    'severity_class = "P0"',
                    'threat_assumption = "TA-3"',
                    'runner = "renode_nrf52840"',
                    'verification_scope = "renode"',
                    'expected_outcome = "exploit_poc"',
                    'invariant_id = "INV-STAGE0-LOCK"',
                    'root_cause_key = "tamper-test"',
                ]),
                encoding="utf-8",
            )
            (bdir / "scenario.json").write_text('{"action":"flash_overlay"}', encoding="utf-8")
            (bdir / "oracle.json").write_text('{}', encoding="utf-8")
            (bdir / "payload" / "override.resc").write_text("machine Reset", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Forbidden payload extension"):
                jr.load_and_validate_bundle(bdir)

    def test_rejects_path_traversal_outside_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bdir = Path(td) / "ATK-9998-nrf52840-runtime-escape"
            bdir.mkdir(parents=True)
            (bdir / "attack.toml").write_text(
                "\n".join([
                    'id = "ATK-9998"',
                    'title = "Path Escape"',
                    'team = "team-2"',
                    'chip = "nrf52840"',
                    'phase = "runtime"',
                    'severity_class = "P0"',
                    'threat_assumption = "TA-3"',
                    'runner = "renode_nrf52840"',
                    'verification_scope = "renode"',
                    'expected_outcome = "exploit_poc"',
                    'invariant_id = "INV-STAGE0-LOCK"',
                    'root_cause_key = "escape-test"',
                ]),
                encoding="utf-8",
            )
            (bdir / "scenario.json").write_text(
                json.dumps({"action": "build_malicious_app", "source_file": "../../toobloader/core/boot_main.c"}),
                encoding="utf-8",
            )
            (bdir / "oracle.json").write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Unsafe path reference"):
                jr.load_and_validate_bundle(bdir)

    def test_severity_weighted_dedup_scoreboard(self) -> None:
        def _mk(bid: str, team: str, sev: str, verdict: str, rc: str) -> jr.BundleVerdict:
            return jr.BundleVerdict(
                id=bid,
                title=bid,
                team=team,
                chip="nrf52840",
                phase="runtime",
                runner="renode_nrf52840",
                severity_class=sev,
                verification_scope="renode",
                expected_outcome="exploit_poc",
                invariant_id="INV",
                root_cause_key=rc,
                verdict=verdict,
                points=0,
                duplicate_of=None,
                elapsed_s=1.0,
                detail="test",
            )

        rows = [
            _mk("ATK-A", "team-1", "P0", "EXPLOIT_CONFIRMED", "rc-k4-bypass"),
            _mk("ATK-B", "team-2", "P0", "EXPLOIT_CONFIRMED", "rc-k4-bypass"),  # duplicate
            _mk("ATK-C", "team-2", "P1", "EXPLOIT_CONFIRMED", "rc-sram-leak"),
            _mk("ATK-D", "team-4", "P3", "EMULATOR_MODEL_GAP", "rc-emfi"),
            _mk("ATK-E", "team-1", "P2", "DEFENDED_PASS", "rc-defended"),
        ]
        scored, teams = jr.compute_scoreboard(rows, mode="judge")
        self.assertEqual(scored[0].points, 100)
        self.assertEqual(scored[1].points, 0)
        self.assertEqual(scored[1].duplicate_of, "ATK-A")
        self.assertEqual(scored[2].points, 50)
        self.assertEqual(scored[3].points, 0)
        self.assertEqual(scored[4].points, 0)
        self.assertEqual(teams["team-1"], 100)
        self.assertEqual(teams["team-2"], 50)
        self.assertEqual(teams["team-4"], 0)


if __name__ == "__main__":
    unittest.main()
