#!/usr/bin/env python3
"""Independent Toob-Loader Attack-Corpus & Red-Team Judge Runner.

Evaluates declarative attack bundles against unmodified production builds and
emulators (Renode nRF52840, QEMU ESP32-C6, CLI build gates, Host-SIL ASan/UBSan).
Strictly separates untrusted submissions from target firmware/emulators and scores
only verified, root-cause-deduplicated findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "test" / "fih_emu"))
import fih_fault_campaign as fih  # noqa: E402


SCORE_TABLE: Dict[str, int] = {
    "P0": 100,
    "P1": 50,
    "P2": 25,
    "P3": 75,
}

REQUIRED_META_FIELDS = (
    "id",
    "title",
    "team",
    "chip",
    "phase",
    "severity_class",
    "threat_assumption",
    "runner",
    "verification_scope",
    "expected_outcome",
    "invariant_id",
    "root_cause_key",
)

ALLOWED_SEVERITIES = {"P0", "P1", "P2", "P3"}
ALLOWED_PHASES = {"preboot", "provisioning", "update", "rollback", "recovery", "runtime", "build"}
ALLOWED_RUNNERS = {"renode_nrf52840", "qemu_esp32c6", "build_gates", "host_sil", "fih_emu"}
ALLOWED_SCOPES = {"host_sil", "renode", "qemu", "fih_emu", "build_gates", "silicon_audit_required"}
ALLOWED_EXPECTED = {"defended", "exploit_poc"}

FORBIDDEN_PAYLOAD_EXTS = {
    ".resc",
    ".repl",
    ".cs",
    ".py",
    ".ps1",
    ".sh",
    ".bat",
    ".cmd",
    ".exe",
    ".dll",
    ".so",
}

FORBIDDEN_TARGET_PATHS = (
    "toobloader/",
    "cmake/",
    "recovery/",
    "sdk/",
    "common/",
    "toob-go-lib/",
    "cli/",
    "test/renode_",
    "test/qemu_",
    "scripts/",
)

# ESP32-C6 flash & eFuse geometry matching test/qemu_esp32c6/qemu_esp32c6_e2e_test.go
ESP32C6_FLASH_SIZE = 4 * 1024 * 1024
ESP32C6_EFUSE_SIZE = 2048
ESP32C6_OFF_STAGE0 = 0x000000
ESP32C6_OFF_STAGE1A = 0x008000
ESP32C6_OFF_STAGE1B = 0x028000
ESP32C6_OFF_APP_SLOT0 = 0x050000
ESP32C6_OFF_RECOVERY = 0x110000
ESP32C6_EFUSE_MAC = 0x18
ESP32C6_EFUSE_USER = 0x50
ESP32C6_EFUSE_KEY0 = 0x70


@dataclass
class AttackBundle:
    bundle_dir: Path
    meta: Dict[str, Any]
    scenario: Dict[str, Any]
    oracle: Dict[str, Any]


@dataclass
class BundleVerdict:
    id: str
    title: str
    team: str
    chip: str
    phase: str
    runner: str
    severity_class: str
    verification_scope: str
    expected_outcome: str
    invariant_id: str
    root_cause_key: str
    verdict: str
    points: int
    duplicate_of: Optional[str]
    elapsed_s: float
    detail: str


def validate_safe_relpath(base_dir: Path, rel: str) -> Path:
    """Resolve rel inside base_dir, rejecting absolute paths, .. escapes, and symlinks."""
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError(f"Unsafe path reference outside bundle: {rel!r}")
    candidate = base_dir / rel_path
    resolved_base = base_dir.resolve()
    resolved_cand = candidate.resolve()
    if resolved_cand != resolved_base and resolved_base not in resolved_cand.parents:
        raise ValueError(f"Path traversal blocked: {rel!r}")
    # Check every existing component in the path for symlinks
    cur = base_dir
    for part in rel_path.parts:
        cur = cur / part
        if cur.exists() and cur.is_symlink():
            raise ValueError(f"Symlinks forbidden in attack bundles: {cur}")
    return resolved_cand


def check_payload_tree(bundle_dir: Path) -> None:
    """Enforce zero symlinks and zero forbidden executable/emulator file extensions."""
    payload_dir = bundle_dir / "payload"
    if not payload_dir.exists():
        return
    if payload_dir.is_symlink():
        raise ValueError(f"Symlink payload dir forbidden: {payload_dir}")
    for root, dirs, files in os.walk(payload_dir):
        root_p = Path(root)
        for d in dirs:
            dp = root_p / d
            if dp.is_symlink():
                raise ValueError(f"Symlink directory forbidden in payload: {dp}")
        for name in files:
            fp = root_p / name
            if fp.is_symlink():
                raise ValueError(f"Symlink file forbidden in payload: {fp}")
            if fp.suffix.lower() in FORBIDDEN_PAYLOAD_EXTS:
                raise ValueError(f"Forbidden payload extension {fp.suffix!r} in {fp.name}")


def load_and_validate_bundle(bundle_dir: Path) -> AttackBundle:
    """Load and structurally validate attack.toml, scenario.json, oracle.json, and payload."""
    for req_file in ("attack.toml", "scenario.json", "oracle.json"):
        p = bundle_dir / req_file
        if not p.is_file() or p.is_symlink():
            raise ValueError(f"Missing required bundle file: {p}")

    meta = tomllib.loads((bundle_dir / "attack.toml").read_text(encoding="utf-8"))
    for field in REQUIRED_META_FIELDS:
        if field not in meta or not isinstance(meta[field], str) or not meta[field].strip():
            raise ValueError(f"Missing or empty metadata field {field!r} in attack.toml")

    if meta["severity_class"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"Invalid severity_class={meta['severity_class']!r}")
    if meta["phase"] not in ALLOWED_PHASES:
        raise ValueError(f"Invalid phase={meta['phase']!r}")
    if meta["runner"] not in ALLOWED_RUNNERS:
        raise ValueError(f"Invalid runner={meta['runner']!r}")
    if meta["verification_scope"] not in ALLOWED_SCOPES:
        raise ValueError(f"Invalid verification_scope={meta['verification_scope']!r}")
    if meta["expected_outcome"] not in ALLOWED_EXPECTED:
        raise ValueError(f"Invalid expected_outcome={meta['expected_outcome']!r}")
    if not bundle_dir.name.startswith(meta["id"]):
        raise ValueError(f"Bundle directory {bundle_dir.name!r} must start with id {meta['id']!r}")

    scenario = json.loads((bundle_dir / "scenario.json").read_text(encoding="utf-8"))
    oracle = json.loads((bundle_dir / "oracle.json").read_text(encoding="utf-8"))
    if not isinstance(scenario, dict) or not isinstance(oracle, dict):
        raise ValueError("scenario.json and oracle.json must be JSON objects")

    check_payload_tree(bundle_dir)

    for key in ("source_file", "package_dir", "payload_file"):
        if key in scenario and isinstance(scenario[key], str):
            validate_safe_relpath(bundle_dir, scenario[key])
    for step in scenario.get("overlays", []):
        if isinstance(step, dict) and isinstance(step.get("payload_file"), str):
            validate_safe_relpath(bundle_dir, step["payload_file"])

    return AttackBundle(bundle_dir=bundle_dir, meta=meta, scenario=scenario, oracle=oracle)


def verify_clean_target_tree(repo_root: Path) -> Optional[str]:
    """Ensure Red-Team runs did not modify protected firmware, build, or emulator files."""
    res = subprocess.run(
        ["git", "-C", str(repo_root), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return f"git status failed: {res.stderr.strip()}"
    violations: List[str] = []
    for line in res.stdout.splitlines():
        if len(line) < 4:
            continue
        rel = line[3:].strip().replace("\\", "/")
        if " -> " in rel:
            rel = rel.split(" -> ", 1)[1].strip()
        for prefix in FORBIDDEN_TARGET_PATHS:
            if rel.startswith(prefix):
                violations.append(rel)
                break
    if violations:
        return "Protected target files modified: " + ", ".join(violations[:10])
    return None


def find_toob_cli(repo_root: Path) -> Path:
    candidates = []
    env_cli = os.environ.get("TOOB_CLI_BIN")
    if env_cli:
        candidates.append(Path(env_cli))
    candidates.extend([
        repo_root / "toob.exe",
        repo_root / "cli" / "toob-cli" / "toob.exe",
    ])
    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError("toob.exe not found (build cli/toob-cli or set TOOB_CLI_BIN)")


def find_qemu_esp32c6() -> Tuple[Path, Path]:
    exe = "qemu-system-riscv32.exe" if os.name == "nt" else "qemu-system-riscv32"
    env_bin = os.environ.get("TOOB_QEMU_ESP_DEV_BIN")
    if env_bin:
        p = Path(env_bin)
        if p.is_file():
            return p, p.parent.parent / "share" / "qemu"
    default_bin = Path(r"D:\ToobStorage\tools\qemu-esp-dev\bin") / exe
    default_share = Path(r"D:\ToobStorage\tools\qemu-esp-dev\share\qemu")
    if default_bin.is_file():
        return default_bin, default_share
    which_p = shutil.which(exe)
    if which_p:
        p = Path(which_p)
        return p, p.parent.parent / "share" / "qemu"
    raise FileNotFoundError("qemu-system-riscv32 not found (set TOOB_QEMU_ESP_DEV_BIN)")


def apply_binary_overlays(buf: bytearray, bundle_dir: Path, overlays: Sequence[Dict[str, Any]]) -> None:
    """Apply declarative offset patches (fill_byte, hex_bytes, or payload_file) to flash/efuse image."""
    for ov in overlays:
        off_raw = ov["offset"]
        off = int(off_raw, 0) if isinstance(off_raw, str) else int(off_raw)
        if "fill_byte" in ov and "length" in ov:
            val = int(ov["fill_byte"], 0) if isinstance(ov["fill_byte"], str) else int(ov["fill_byte"])
            length_raw = ov["length"]
            length = int(length_raw, 0) if isinstance(length_raw, str) else int(length_raw)
            patch = bytes([val & 0xFF]) * length
        elif "hex_bytes" in ov:
            patch = bytes.fromhex(ov["hex_bytes"])
        elif "payload_file" in ov:
            patch = validate_safe_relpath(bundle_dir, ov["payload_file"]).read_bytes()
        else:
            raise ValueError(f"Unsupported overlay specification: {ov}")
        if off < 0 or off + len(patch) > len(buf):
            raise ValueError(f"Overlay out of image bounds: off=0x{off:x} len={len(patch)}")
        buf[off : off + len(patch)] = patch


def evaluate_uart_and_oracle(
    uart_text: str,
    oracle: Dict[str, Any],
    bprot_blocked: Optional[int] = None,
    stage0_unchanged: Optional[bool] = None,
) -> Optional[str]:
    """Return failure reason (meaning exploit/breach occurred or check failed), or None if defended."""
    for needle in oracle.get("must_contain_uart", []):
        if needle not in uart_text:
            return f"missing expected UART marker {needle!r}"
    for forbidden in oracle.get("must_not_contain_uart", []):
        if forbidden in uart_text:
            return f"forbidden UART marker {forbidden!r} observed"
    if "bprot_blocked_min" in oracle:
        req = int(oracle["bprot_blocked_min"])
        if bprot_blocked is None or bprot_blocked < req:
            return f"powerBprot BlockedOperations={bprot_blocked} < required {req}"
    if oracle.get("stage0_sha256_unchanged") and stage0_unchanged is False:
        return "Stage-0 flash slice SHA-256 changed"
    return None


class JudgeRunner:
    """Executes attack bundles against isolated unmodified production baselines."""

    def __init__(self, work_dir: Path, repo_root: Path = REPO_ROOT) -> None:
        self.repo_root = repo_root
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.toob_cli = find_toob_cli(repo_root)
        self._nrf_baseline: Optional[Tuple[Path, Path]] = None
        self._esp32c6_artifacts: Optional[Dict[str, Path]] = None

    def ensure_nrf_baseline(self) -> Tuple[Path, Path, Path]:
        renode_bin = fih.find_renode_bin()
        if not renode_bin:
            raise FileNotFoundError("Renode binary not found (set TOOB_RENODE_BIN)")
        build_dir = self.repo_root / "test" / "renode_nrf52840" / "builds" / "build_nrf52840"
        if not (build_dir / "toob_stage0.bin").is_file():
            subprocess.check_call(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(self.repo_root / "scripts" / "run_renode_nrf52840_e2e.ps1"),
                ],
                cwd=str(self.repo_root),
            )
        if self._nrf_baseline is None:
            base_dir = self.work_dir / "nrf52840_baseline"
            base_dir.mkdir(parents=True, exist_ok=True)
            self._nrf_baseline = fih.provision_baseline(renode_bin, base_dir)
        return renode_bin, self._nrf_baseline[0], self._nrf_baseline[1]

    def ensure_esp32c6_artifacts(self) -> Tuple[Path, Path, Dict[str, Path]]:
        qemu_bin, qemu_share = find_qemu_esp32c6()
        if self._esp32c6_artifacts is None:
            bdir = self.work_dir / "esp32c6_build"
            bdir.mkdir(parents=True, exist_ok=True)
            stage0_bin = bdir / "toob_stage0.esp.bin"
            stage1_bin = bdir / "toob_stage1.signed.bin"
            rec_bin = bdir / "toob_recovery.bin"
            if not (stage0_bin.is_file() and stage1_bin.is_file() and rec_bin.is_file()):
                env = os.environ.copy()
                env["TOOB_REGISTRY_DIR"] = str(self.repo_root / "toob-infra" / "registry" / "packages")
                if not env.get("TOOB_HOME") and Path(r"D:\ToobStorage\.toob").is_dir():
                    env["TOOB_HOME"] = r"D:\ToobStorage\.toob"

                build_cmd = [
                    str(self.toob_cli),
                    "build",
                    "--manifest",
                    str(self.repo_root / "test" / "qemu_esp32c6" / "device.toml"),
                    "--build-dir",
                    str(bdir),
                    "--profile",
                    "production",
                    "--native",
                    "--dev",
                    "--skip-checks",
                ]
                gcc_exe = "riscv32-esp-elf-gcc.exe" if os.name == "nt" else "riscv32-esp-elf-gcc"
                tc_candidates = [
                    os.environ.get("TOOB_RISCV32_ESP_TOOLCHAIN"),
                    r"D:\ToobStorage\.toob\toolchains\riscv32-esp-elf\13.2.0_20230928\riscv32-esp-elf",
                    str(Path.home() / ".toob" / "toolchains" / "riscv32-esp-elf" / "13.2.0_20230928" / "riscv32-esp-elf"),
                ]
                for tc_raw in tc_candidates:
                    if tc_raw and (Path(tc_raw) / "bin" / gcc_exe).is_file():
                        build_cmd.extend(["--toolchain-path", tc_raw])
                        break

                subprocess.check_call(build_cmd, cwd=str(self.repo_root), env=env)
                subprocess.check_call(
                    [
                        str(self.toob_cli),
                        "sign",
                        "stage0",
                        str(bdir / "toob_stage0"),
                        "--chip",
                        "esp32c6",
                        "-o",
                        str(stage0_bin),
                    ],
                    cwd=str(self.repo_root),
                    env=env,
                )
                subprocess.check_call(
                    [
                        str(self.toob_cli),
                        "sign",
                        "stage1",
                        str(bdir / "toob_stage1.bin"),
                        "--chip",
                        "esp32c6",
                        "--entry",
                        "0x40810000",
                        "--mock",
                        "-o",
                        str(stage1_bin),
                    ],
                    cwd=str(self.repo_root),
                    env=env,
                )
                if not rec_bin.is_file() and (bdir / "toob_recovery.raw.bin").is_file():
                    subprocess.check_call(
                        [
                            str(self.toob_cli),
                            "sign",
                            "image",
                            str(bdir / "toob_recovery.raw.bin"),
                            "--role",
                            "recovery",
                            "--chip",
                            "esp32c6",
                            "--entry",
                            "0x14",
                            "--mock",
                            "-o",
                            str(rec_bin),
                        ],
                        cwd=str(self.repo_root),
                        env=env,
                    )
            self._esp32c6_artifacts = {
                "stage0": stage0_bin,
                "stage1": stage1_bin,
                "recovery": rec_bin,
            }
        return qemu_bin, qemu_share, self._esp32c6_artifacts

    def compile_malicious_nrf_app(self, bundle_dir: Path, src_rel: str, run_dir: Path) -> bytes:
        src_path = validate_safe_relpath(bundle_dir, src_rel)
        build_dir = self.repo_root / "test" / "renode_nrf52840" / "builds" / "build_nrf52840"
        exe_suffix = ".exe" if os.name == "nt" else ""
        arm_gcc = fih.find_arm_tool(f"arm-none-eabi-gcc{exe_suffix}")
        arm_objcopy = fih.find_arm_tool(f"arm-none-eabi-objcopy{exe_suffix}")

        elf = run_dir / "attack_app.elf"
        raw = run_dir / "attack_app.raw.bin"
        toob = run_dir / "attack_app.toob"
        probe_ld = self.repo_root / "test" / "fih_emu" / "probe_app_fault_test" / "probe_nrf52840.ld"

        flags = [
            str(arm_gcc),
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=soft",
            "-fno-short-enums",
            "-Os",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-common",
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "--specs=nano.specs",
            "--specs=nosys.specs",
            "-nostartfiles",
            "-Wl,--gc-sections",
            "-Wl,--no-enum-size-warning",
            f"-L{build_dir / 'generated'}",
            f"-T{probe_ld}",
            f"-I{build_dir / 'generated'}",
            f"-I{self.repo_root / 'sdk' / 'libtoob' / 'include'}",
            f"-I{self.repo_root / 'common' / 'include'}",
            f"-I{self.repo_root / 'toob-infra' / 'registry' / 'packages' / 'chips' / 'nrf52840'}",
            f"-I{self.repo_root / 'toob-infra' / 'registry' / 'packages' / 'crypto' / 'hash' / 'sha256_sw'}",
            str(src_path),
            str(self.repo_root / "toobloader" / "core" / "utils" / "boot_secure_zeroize.S"),
            str(build_dir / "libtoob_libtoob.a"),
            str(build_dir / "libtoob_crypto_upstream.a"),
            "-o",
            str(elf),
        ]
        subprocess.check_call(flags, cwd=str(self.repo_root))
        subprocess.check_call([str(arm_objcopy), "-O", "binary", str(elf), str(raw)])
        subprocess.check_call(
            [str(self.toob_cli), "sign", "image", str(raw), "-o", str(toob), "--entry", "0x100", "--mock"],
            cwd=str(self.repo_root),
        )
        return fih.maybe_resign_tsig_image(toob.read_bytes(), 1)

    def run_renode_nrf52840(self, bundle: AttackBundle) -> Tuple[str, str]:
        renode_bin, flash_prov, uicr_prov = self.ensure_nrf_baseline()
        run_dir = self.work_dir / bundle.meta["id"]
        run_dir.mkdir(parents=True, exist_ok=True)
        action = bundle.scenario.get("action")

        if action == "sram_handoff_audit":
            exe_suffix = ".exe" if os.name == "nt" else ""
            nm_bin = fih.find_arm_tool(f"arm-none-eabi-nm{exe_suffix}")
            build_dir = self.repo_root / "test" / "renode_nrf52840" / "builds" / "build_nrf52840"
            syms_s1 = fih.parse_nm_symbols(nm_bin, build_dir / "toob_stage1")
            ok, findings = fih.run_sram_handover_audit(renode_bin, run_dir, flash_prov, uicr_prov, syms_s1)
            if ok:
                return "DEFENDED_PASS", "SRAM handover audit passed (0 residual secrets)"
            return "EXPLOIT_CONFIRMED", "; ".join(findings)

        flash = bytearray(flash_prov.read_bytes())
        uicr = bytearray(uicr_prov.read_bytes())

        if action == "build_malicious_app":
            app_bytes = self.compile_malicious_nrf_app(bundle.bundle_dir, bundle.scenario["source_file"], run_dir)
            flash[fih.OFF_APP_SLOT0 : fih.OFF_APP_SLOT0 + 0x30000] = b"\xFF" * 0x30000
            flash[fih.OFF_APP_SLOT0 : fih.OFF_APP_SLOT0 + len(app_bytes)] = app_bytes
        elif action == "flash_overlay":
            apply_binary_overlays(flash, bundle.bundle_dir, bundle.scenario.get("overlays", []))
            apply_binary_overlays(uicr, bundle.bundle_dir, bundle.scenario.get("uicr_overlays", []))
        else:
            return "INVALID_SUBMISSION", f"Unsupported renode_nrf52840 action={action!r}"

        stage0_before = hashlib.sha256(bytes(flash[fih.OFF_STAGE0 : fih.OFF_STAGE0 + 0x8000])).hexdigest()
        fp = run_dir / "flash.bin"
        up = run_dir / "uicr.bin"
        fp.write_bytes(flash)
        up.write_bytes(uicr)

        mon_port = fih.reserve_free_port()
        uart_port = fih.reserve_free_port()
        resc = fih.make_base_resc(fp, up, uart_port)
        sess = fih.RenodeSession(renode_bin, run_dir, resc, mon_port, uart_port)
        bprot_blocked: Optional[int] = None
        try:
            sess.start()
            wait_marker = bundle.oracle.get("wait_uart_marker")
            run_secs = float(bundle.scenario.get("run_secs", 2.0))
            if wait_marker:
                sess.wait_uart_bytes(wait_marker.encode("utf-8"), timeout_s=max(run_secs, 12.0))
            else:
                time.sleep(run_secs)
            uart_text = sess.uart_snapshot().decode("utf-8", errors="replace")
            if "bprot_blocked_min" in bundle.oracle:
                sess.exec_mon("pause")
                sess.exec_mon("sysbus.powerBprot BlockedOperations")
                mon_out = sess.wait_mon_text("BlockedOperations", timeout_s=4.0)
                m = re.search(r"BlockedOperations\s*[\r\n]+(0x[0-9a-fA-F]+|\d+)", mon_out)
                bprot_blocked = int(m.group(1), 0) if m else -1
        finally:
            sess.close()

        stage0_after = hashlib.sha256(fp.read_bytes()[fih.OFF_STAGE0 : fih.OFF_STAGE0 + 0x8000]).hexdigest()
        reason = evaluate_uart_and_oracle(
            uart_text,
            bundle.oracle,
            bprot_blocked=bprot_blocked,
            stage0_unchanged=(stage0_before == stage0_after),
        )
        if reason is None:
            return "DEFENDED_PASS", f"bprot_blocked={bprot_blocked}, Stage-0 intact"
        return "EXPLOIT_CONFIRMED", reason

    def run_qemu_esp32c6(self, bundle: AttackBundle) -> Tuple[str, str]:
        qemu_bin, qemu_share, arts = self.ensure_esp32c6_artifacts()
        run_dir = self.work_dir / bundle.meta["id"]
        run_dir.mkdir(parents=True, exist_ok=True)

        flash = bytearray(b"\xFF" * ESP32C6_FLASH_SIZE)
        stage0 = arts["stage0"].read_bytes()
        stage1 = arts["stage1"].read_bytes()
        rec = arts["recovery"].read_bytes()
        flash[ESP32C6_OFF_STAGE0 : ESP32C6_OFF_STAGE0 + len(stage0)] = stage0
        flash[ESP32C6_OFF_STAGE1A : ESP32C6_OFF_STAGE1A + len(stage1)] = stage1
        flash[ESP32C6_OFF_STAGE1B : ESP32C6_OFF_STAGE1B + len(stage1)] = stage1
        flash[ESP32C6_OFF_RECOVERY : ESP32C6_OFF_RECOVERY + len(rec)] = rec

        efuse = bytearray(ESP32C6_EFUSE_SIZE)
        efuse[ESP32C6_EFUSE_MAC : ESP32C6_EFUSE_MAC + 6] = bytes.fromhex("AABBCCDDEE46")
        efuse[ESP32C6_EFUSE_USER] = 0x01
        root_pk = fih.ed25519_public_from_seed(fih.ROOT_SEED)
        efuse[ESP32C6_EFUSE_KEY0 : ESP32C6_EFUSE_KEY0 + 32] = root_pk

        apply_binary_overlays(flash, bundle.bundle_dir, bundle.scenario.get("overlays", []))
        apply_binary_overlays(efuse, bundle.bundle_dir, bundle.scenario.get("efuse_overlays", []))

        fp = run_dir / "flash.bin"
        ep = run_dir / "efuse.bin"
        fp.write_bytes(flash)
        ep.write_bytes(efuse)

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(8.0)
        port = srv.getsockname()[1]

        args = [
            str(qemu_bin),
            "-L",
            str(qemu_share),
            "-accel",
            "tcg,tb-size=32",
            "-machine",
            "esp32c6",
            "-nographic",
            "-serial",
            f"tcp:127.0.0.1:{port}",
            "-monitor",
            "none",
            "-drive",
            f"file={fp},if=mtd,format=raw",
            "-drive",
            f"file={ep},if=none,format=raw,id=efuse",
            "-global",
            "driver=nvram.esp32c6.efuse,property=drive,value=efuse",
        ]

        rx = bytearray()
        stop_ev = threading.Event()
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(run_dir))
        conn: Optional[socket.socket] = None
        try:
            conn, _ = srv.accept()
            conn.settimeout(0.2)

            def _reader() -> None:
                while not stop_ev.is_set():
                    try:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        rx.extend(chunk)
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            thr = threading.Thread(target=_reader, daemon=True)
            thr.start()
            run_secs = float(bundle.scenario.get("run_secs", 4.0))
            deadline = time.time() + run_secs
            wait_marker = bundle.oracle.get("wait_uart_marker")
            while time.time() < deadline:
                if wait_marker and wait_marker.encode("utf-8") in rx:
                    time.sleep(0.4)
                    break
                time.sleep(0.1)
            stop_ev.set()
            thr.join(timeout=1.5)
        finally:
            stop_ev.set()
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
            try:
                srv.close()
            except OSError:
                pass
            proc.terminate()
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)

        uart_text = rx.decode("utf-8", errors="replace")
        reason = evaluate_uart_and_oracle(uart_text, bundle.oracle)
        if reason is None:
            return "DEFENDED_PASS", f"QEMU ESP32-C6 rejected attack ({len(uart_text)} UART bytes)"
        return "EXPLOIT_CONFIRMED", f"{reason} (uart_sample={uart_text[:200]!r})"

    def run_build_gates(self, bundle: AttackBundle) -> Tuple[str, str]:
        gate = bundle.scenario.get("action")
        if gate != "conformance":
            return "INVALID_SUBMISSION", f"Unsupported build_gates action={gate!r}"
        pkg_dir = validate_safe_relpath(bundle.bundle_dir, bundle.scenario["package_dir"])
        res = subprocess.run(
            [str(self.toob_cli), "conformance", str(pkg_dir), "--no-update-check"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        out = (res.stdout + "\n" + res.stderr).strip()
        expect_reject = bool(bundle.oracle.get("expected_gate_reject", True))
        if expect_reject:
            if res.returncode == 0:
                return "EXPLOIT_CONFIRMED", "conformance accepted malicious package (exit 0)"
            req_sub = bundle.oracle.get("expected_diag_substring")
            if req_sub and req_sub not in out:
                return "EXPLOIT_CONFIRMED", f"conformance rejected without {req_sub!r}: {out[:160]}"
            return "DEFENDED_PASS", f"conformance rejected package (exit {res.returncode})"
        return ("DEFENDED_PASS", "ok") if res.returncode == 0 else ("EXPLOIT_CONFIRMED", out[:160])

    def run_host_sil(self, bundle: AttackBundle) -> Tuple[str, str]:
        action = bundle.scenario.get("action")
        if action != "neg_e2e_vectors":
            return "INVALID_SUBMISSION", f"Unsupported host_sil action={action!r}"
        host_dir = self.work_dir / bundle.meta["id"]
        host_dir.mkdir(parents=True, exist_ok=True)
        try:
            fih.build_and_run_neg_e2e(host_dir)
            return "DEFENDED_PASS", "5/5 TA-1 negative vectors passed (ASan+UBSan)"
        except Exception as exc:  # noqa: BLE001
            return "EXPLOIT_CONFIRMED", str(exc)

    def evaluate_bundle(self, bundle: AttackBundle) -> Tuple[str, str]:
        scope = bundle.meta["verification_scope"]
        runner = bundle.meta["runner"]
        if scope == "silicon_audit_required":
            return "EMULATOR_MODEL_GAP", "Marked silicon_audit_required (beyond emulator fidelity)"
        if runner == "renode_nrf52840":
            return self.run_renode_nrf52840(bundle)
        if runner == "qemu_esp32c6":
            return self.run_qemu_esp32c6(bundle)
        if runner == "build_gates":
            return self.run_build_gates(bundle)
        if runner == "host_sil":
            return self.run_host_sil(bundle)
        return "EMULATOR_MODEL_GAP", f"Runner {runner!r} not enabled in this tier"


def compute_scoreboard(verdicts: Sequence[BundleVerdict], mode: str) -> Tuple[List[BundleVerdict], Dict[str, int]]:
    """Apply root-cause deduplication and severity-weighted scoring."""
    seen_causes: Dict[str, str] = {}
    team_scores: Dict[str, int] = {}
    updated: List[BundleVerdict] = []

    for v in verdicts:
        team_scores.setdefault(v.team, 0)
        pts = 0
        dup_of = None
        if v.verdict == "EXPLOIT_CONFIRMED":
            rc = v.root_cause_key
            if rc in seen_causes:
                dup_of = seen_causes[rc]
            else:
                seen_causes[rc] = v.id
                pts = SCORE_TABLE.get(v.severity_class, 0)
        elif mode == "regression" and v.verdict == "DEFENDED_PASS":
            pts = 0
        team_scores[v.team] += pts
        updated.append(
            BundleVerdict(
                **{
                    **asdict(v),
                    "points": pts,
                    "duplicate_of": dup_of,
                }
            )
        )
    return updated, team_scores


def render_reports(
    out_dir: Path,
    mode: str,
    verdicts: Sequence[BundleVerdict],
    team_scores: Dict[str, int],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "mode": mode,
        "total": len(verdicts),
        "defended_pass": sum(1 for v in verdicts if v.verdict == "DEFENDED_PASS"),
        "exploits_confirmed": sum(1 for v in verdicts if v.verdict == "EXPLOIT_CONFIRMED"),
        "emulator_model_gap": sum(1 for v in verdicts if v.verdict == "EMULATOR_MODEL_GAP"),
        "invalid_submission": sum(1 for v in verdicts if v.verdict == "INVALID_SUBMISSION"),
        "team_scores": team_scores,
        "bundles": [asdict(v) for v in verdicts],
    }
    (out_dir / "judge_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        f"# Toob-Loader Attack-Corpus Judge Scoreboard (`mode={mode}`)",
        "",
        "## Team Scores (Deduplicated by `root_cause_key`)",
        "",
        "| Team | Points |",
        "| :--- | :---: |",
    ]
    for team, pts in sorted(team_scores.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{team}` | **{pts}** |")
    lines.extend([
        "",
        "## Bundle Verdicts",
        "",
        "| ID | Team | Chip | Phase | Runner | Sev | Verdict | Pts | Time | Detail |",
        "| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :---: | :---: | :--- |",
    ])
    for v in verdicts:
        lines.append(
            f"| `{v.id}` | `{v.team}` | `{v.chip}` | `{v.phase}` | `{v.runner}` | `{v.severity_class}` "
            f"| `{v.verdict}` | {v.points} | {v.elapsed_s:.2f}s | {v.detail} |"
        )
    (out_dir / "scoreboard.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def discover_bundles(root_dir: Path, filter_substr: str = "") -> List[Path]:
    if not root_dir.exists():
        return []
    out = []
    for child in sorted(root_dir.iterdir()):
        if not child.is_dir() or not child.name.startswith("ATK-"):
            continue
        if filter_substr and filter_substr.lower() not in child.name.lower():
            continue
        out.append(child)
    return out


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Independent Toob-Loader Attack-Corpus Judge")
    ap.add_argument("--corpus-dir", type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument("--submissions-dir", type=Path, default=None)
    ap.add_argument("--mode", choices=("regression", "judge"), default="regression")
    ap.add_argument("--filter", default="")
    ap.add_argument("--backend", default="")
    ap.add_argument("--quick", action="store_true", help="Run only build_gates + host_sil bundles")
    ap.add_argument("--work-dir", type=Path, default=Path(tempfile.gettempdir()) / "attack_corpus_work")
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--verify-clean-target", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    target_dir = args.submissions_dir if args.submissions_dir else args.corpus_dir
    out_dir = args.out_dir if args.out_dir else (args.work_dir / "reports")

    if args.verify_clean_target:
        err = verify_clean_target_tree(REPO_ROOT)
        if err:
            print(f"INVALID_SUBMISSION clean_target_check=FAIL detail={err}")
            return 2

    bundle_dirs = discover_bundles(target_dir, args.filter)
    if not bundle_dirs:
        print(f"No attack bundles found under {target_dir}")
        return 2

    runner: Optional[JudgeRunner] = None
    raw_verdicts: List[BundleVerdict] = []

    for bdir in bundle_dirs:
        t0 = time.monotonic()
        try:
            bundle = load_and_validate_bundle(bdir)
        except Exception as exc:  # noqa: BLE001
            raw_verdicts.append(
                BundleVerdict(
                    id=bdir.name,
                    title="invalid",
                    team="unknown",
                    chip="unknown",
                    phase="preboot",
                    runner="unknown",
                    severity_class="P0",
                    verification_scope="host_sil",
                    expected_outcome="defended",
                    invariant_id="invalid",
                    root_cause_key=f"invalid:{bdir.name}",
                    verdict="INVALID_SUBMISSION",
                    points=0,
                    duplicate_of=None,
                    elapsed_s=round(time.monotonic() - t0, 2),
                    detail=str(exc),
                )
            )
            continue

        if args.backend and bundle.meta["runner"] != args.backend:
            continue
        if args.quick and bundle.meta["runner"] not in ("build_gates", "host_sil"):
            continue

        if runner is None:
            runner = JudgeRunner(args.work_dir)

        try:
            verdict_str, detail = runner.evaluate_bundle(bundle)
        except Exception as exc:  # noqa: BLE001
            verdict_str, detail = "INVALID_SUBMISSION", f"Execution error: {exc}"

        elapsed = round(time.monotonic() - t0, 2)
        m = bundle.meta
        print(
            f"JUDGE_BUNDLE id={m['id']} team={m['team']} chip={m['chip']} "
            f"runner={m['runner']} verdict={verdict_str} time={elapsed:.2f}s detail={detail}"
        )
        raw_verdicts.append(
            BundleVerdict(
                id=m["id"],
                title=m["title"],
                team=m["team"],
                chip=m["chip"],
                phase=m["phase"],
                runner=m["runner"],
                severity_class=m["severity_class"],
                verification_scope=m["verification_scope"],
                expected_outcome=m["expected_outcome"],
                invariant_id=m["invariant_id"],
                root_cause_key=m["root_cause_key"],
                verdict=verdict_str,
                points=0,
                duplicate_of=None,
                elapsed_s=elapsed,
                detail=detail,
            )
        )

    final_verdicts, team_scores = compute_scoreboard(raw_verdicts, args.mode)
    render_reports(out_dir, args.mode, final_verdicts, team_scores)

    defended = sum(1 for v in final_verdicts if v.verdict == "DEFENDED_PASS")
    exploits = sum(1 for v in final_verdicts if v.verdict == "EXPLOIT_CONFIRMED")
    invalid = sum(1 for v in final_verdicts if v.verdict == "INVALID_SUBMISSION")
    gaps = sum(1 for v in final_verdicts if v.verdict == "EMULATOR_MODEL_GAP")
    status = "PASS"
    if args.mode == "regression" and (exploits > 0 or invalid > 0):
        status = "FAIL"

    print(
        f"ATTACK_CORPUS_SUMMARY mode={args.mode} total={len(final_verdicts)} "
        f"defended={defended} exploits_confirmed={exploits} gaps={gaps} invalid={invalid} "
        f"report={out_dir / 'scoreboard.md'} status={status}"
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
