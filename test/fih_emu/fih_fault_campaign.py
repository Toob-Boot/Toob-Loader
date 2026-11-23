#!/usr/bin/env python3
"""
Tier 2 FIH Machine-Code Fault Injection, SRAM Handover Audit & Negative Security E2E Suite.

Modes:
  --dry-run   Inspect Stage 0 & Stage 1 ELFs (arm-none-eabi-nm / objdump), validate
              sram_handover_audit.resc, compile & sign probe_app_fault_test, and build +
              run neg_e2e_vectors under Clang ASan+UBSan.
  --full      Run everything in --dry-run PLUS headless Renode 1.17.0 nRF52840 emulation:
                1. Factory COBS provisioning baseline
                2. SRAM handover secret cleanup audit (sram_handover_audit.resc)
                3. probe_app_fault_test BPROT / NVMC / MPU hardware probe
                4. Live Renode negative security E2E scenarios
                5. Machine-code FIH campaign (single/double PC skip & R0..R3 register flips)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Pure-Python RFC 8032 Ed25519 (zero external dependencies)
# ---------------------------------------------------------------------------

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x % _Q, _Q - 2, _Q)


_D = (-121665 * _inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q, 1, (_BX * _BY) % _Q)


def _ed_add(p: Tuple[int, int, int, int], q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (2 * _D * t1 * t2) % _Q
    d = (2 * z1 * z2) % _Q
    e = (b - a) % _Q
    f = (d - c) % _Q
    g = (d + c) % _Q
    h = (b + a) % _Q
    return (e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q


def _ed_scalarmult(p: Tuple[int, int, int, int], e: int) -> Tuple[int, int, int, int]:
    acc = (0, 1, 1, 0)
    cur = p
    while e > 0:
        if e & 1:
            acc = _ed_add(acc, cur)
        cur = _ed_add(cur, cur)
        e >>= 1
    return acc


def _ed_encodepoint(p: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    xp = (x * zi) % _Q
    yp = (y * zi) % _Q
    bits = bytearray(yp.to_bytes(32, "little"))
    if xp & 1:
        bits[31] |= 0x80
    return bytes(bits)


def _ed_hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def ed25519_public_from_seed(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _ed_encodepoint(_ed_scalarmult(_B, a))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pk = _ed_encodepoint(_ed_scalarmult(_B, a))
    r = _ed_hint(h[32:64] + msg)
    cap_r = _ed_encodepoint(_ed_scalarmult(_B, r))
    k = _ed_hint(cap_r + pk + msg)
    s = (r + k * a) % _L
    return cap_r + s.to_bytes(32, "little")


def verify_ed25519_rfc8032_selftest() -> None:
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    exp_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    exp_sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert ed25519_public_from_seed(seed) == exp_pk, "Ed25519 pubkey KAT mismatch"
    assert ed25519_sign(seed, b"") == exp_sig, "Ed25519 RFC 8032 TV1 signature mismatch"


# ---------------------------------------------------------------------------
# Repository / Toolchain Constants & Paths
# ---------------------------------------------------------------------------

ROOT_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

FLASH_TOTAL_SIZE = 0x100000
UICR_TOTAL_SIZE = 0x1000

OFF_STAGE0 = 0x000000
OFF_STAGE1A = 0x008000
OFF_STAGE1B = 0x020000
OFF_APP_SLOT0 = 0x038000
OFF_STAGING = 0x068000
OFF_RECOVERY = 0x098000
OFF_WAL = 0x0D8000
WAL_SIZE = 0x004000

UICR_OFF_KEY0 = 0x080
UICR_OFF_KEY1 = 0x0A0
UICR_OFF_DSLC = 0x0C0
UICR_OFF_LOCK = 0x0CC

TSIG_MAGIC = 0x54534947
TSIG_FLAG_SHA256 = 0x01
TSIG_TRAILER_LEN = 72
BOOT_OK_U32 = 0x55AA55AA

PROV_CMD_BURN_KEY = 0x01
PROV_CMD_SET_DSLC = 0x02
PROV_CMD_READ_ID = 0x06
PROV_CMD_LOCK_BOOT_FLASH = 0x07
PROV_CMD_REBOOT = 0xFF


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_arm_tool(name: str) -> Path:
    home = Path.home()
    cand = home / ".toob" / "toolchains" / "arm-none-eabi" / "15.2.1-1.1" / "xpack-arm-none-eabi-gcc-15.2.1-1.1" / "bin" / name
    if cand.exists():
        return cand
    found = shutil.which(name)
    if found:
        return Path(found)
    raise FileNotFoundError(f"Missing ARM toolchain binary: {name}")


def find_renode_bin() -> Optional[Path]:
    env_bin = os.environ.get("TOOB_RENODE_BIN")
    if env_bin and Path(env_bin).exists():
        return Path(env_bin)
    exe = "renode.exe" if os.name == "nt" else "renode"
    cand = Path.home() / ".toob" / "tools" / "renode" / "renode_1.17.0-portable" / exe
    if cand.exists():
        return cand
    found = shutil.which(exe)
    return Path(found) if found else None


def find_clang_bin() -> Path:
    for cand in [Path(r"C:\Program Files\LLVM\bin\clang.exe"), Path(shutil.which("clang") or "")]:
        if cand.is_file():
            return cand
    raise FileNotFoundError("Missing clang binary for neg_e2e_vectors compilation")


# ---------------------------------------------------------------------------
# ELF Inspection & Security Target Discovery
# ---------------------------------------------------------------------------

@dataclass
class InsnSite:
    stage: str
    function: str
    pc: int
    width: int
    mnemonic: str
    next_width: int
    kind: str  # "branch_cmp" | "glitch_gate" | "call_check"


def parse_nm_symbols(nm_bin: Path, elf_path: Path) -> Dict[str, Tuple[int, int]]:
    out = subprocess.check_output([str(nm_bin), "-n", "-S", str(elf_path)], text=True)
    syms: Dict[str, Tuple[int, int]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4:
            addr = int(parts[0], 16)
            size = int(parts[1], 16)
            name = parts[3]
            syms[name] = (addr, size)
        elif len(parts) == 3:
            addr = int(parts[0], 16)
            name = parts[2]
            syms.setdefault(name, (addr, 0))
    return syms


def parse_disassembly_targets(
    objdump_bin: Path,
    elf_path: Path,
    stage: str,
    target_prefixes: Tuple[str, ...],
) -> Tuple[List[InsnSite], List[int]]:
    dis = subprocess.check_output([str(objdump_bin), "-d", str(elf_path)], text=True)
    func_hdr_re = re.compile(r"^([0-9a-fA-F]+)\s+<([^>]+)>:")
    insn_re = re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]+(?:\s+[0-9a-fA-F]+)?)\s+(\S+)(.*)$")

    cur_func = ""
    insns_by_func: Dict[str, List[Tuple[int, int, str, str]]] = {}
    for line in dis.splitlines():
        m_hdr = func_hdr_re.match(line)
        if m_hdr:
            cur_func = m_hdr.group(2)
            continue
        if not cur_func or not any(cur_func.startswith(p) for p in target_prefixes):
            continue
        m_insn = insn_re.match(line)
        if not m_insn:
            continue
        pc = int(m_insn.group(1), 16)
        raw_hex = m_insn.group(2).replace(" ", "")
        width = 4 if len(raw_hex) >= 8 else 2
        mnemonic = m_insn.group(3).lower()
        operands = m_insn.group(4).strip()
        insns_by_func.setdefault(cur_func, []).append((pc, width, mnemonic, operands))

    sites: List[InsnSite] = []
    seen_pcs = set()
    glitch_gate_pcs: List[int] = []

    cond_mnemonics = {
        "cmp", "cmn", "tst", "cbz", "cbnz",
        "beq.n", "bne.n", "beq.w", "bne.w", "beq", "bne",
        "bls.n", "bhi.n", "bls.w", "bhi.w", "bge.n", "blt.n",
        "ble.n", "bgt.n", "bcc.n", "bcs.n",
    }

    for func_name, ilist in insns_by_func.items():
        for idx, (pc, width, mnem, operands) in enumerate(ilist):
            nxt_w = ilist[idx + 1][1] if (idx + 1) < len(ilist) else 2
            # Detect BOOT_GLITCH_DELAY() triple-NOP sled (`nop; nop; nop`)
            if (
                idx + 2 < len(ilist)
                and mnem == "nop"
                and ilist[idx + 1][2] == "nop"
                and ilist[idx + 2][2] == "nop"
            ):
                glitch_gate_pcs.append(pc)
                if idx + 3 < len(ilist):
                    g_pc, g_w, g_mnem, _ = ilist[idx + 3]
                    g_nw = ilist[idx + 4][1] if (idx + 4) < len(ilist) else 2
                    if g_pc not in seen_pcs:
                        seen_pcs.add(g_pc)
                        sites.append(InsnSite(stage, func_name, g_pc, g_w, g_mnem, g_nw, "glitch_gate"))
                continue

            is_sec_call = mnem in ("bl", "blx") and any(
                k in operands
                for k in (
                    "stage0_verify_signature",
                    "boot_verify",
                    "verify",
                    "crypto",
                    "boot_journal",
                    "constant_time",
                    "read_dslc",
                    "lockdown",
                )
            )
            if mnem in cond_mnemonics or is_sec_call:
                kind = "call_check" if is_sec_call else "branch_cmp"
                if pc not in seen_pcs:
                    seen_pcs.add(pc)
                    sites.append(InsnSite(stage, func_name, pc, width, mnem, nxt_w, kind))

    return sites, glitch_gate_pcs


# ---------------------------------------------------------------------------
# Protocol Framing Helpers (COBS, TSIG)
# ---------------------------------------------------------------------------

def cobs_encode(src: bytes) -> bytes:
    out = bytearray([0])
    code_idx = 0
    code = 1
    for b in src:
        if b == 0:
            out[code_idx] = code
            code_idx = len(out)
            out.append(0)
            code = 1
        else:
            out.append(b)
            code += 1
            if code == 0xFF:
                out[code_idx] = code
                code_idx = len(out)
                out.append(0)
                code = 1
    out[code_idx] = code
    out.append(0x00)
    return bytes(out)


def build_prov_frame(cmd: int, payload: bytes = b"") -> bytes:
    body = bytes([cmd]) + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return cobs_encode(body + struct.pack("<I", crc))


def resign_tsig_image(img: bytes, key_index: int, seed: bytes = ROOT_SEED) -> bytes:
    if len(img) < 20 + TSIG_TRAILER_LEN:
        raise ValueError(f"TSIG image too small: {len(img)}")
    out = bytearray(img)
    off = len(out) - TSIG_TRAILER_LEN
    magic = struct.unpack_from("<I", out, off)[0]
    if magic != TSIG_MAGIC:
        raise ValueError(f"Missing TSIG trailer magic: got 0x{magic:08X}")
    out[off + 4] = key_index
    out[off + 5] = TSIG_FLAG_SHA256
    out[off + 6] = 0
    out[off + 7] = 0
    digest = hashlib.sha256(out[:off]).digest()
    sig = ed25519_sign(seed, digest)
    out[off + 8 : off + 72] = sig
    return bytes(out)


def maybe_resign_tsig_image(img: bytes, key_index: int, seed: bytes = ROOT_SEED) -> bytes:
    if len(img) >= 20 + TSIG_TRAILER_LEN:
        off = len(img) - TSIG_TRAILER_LEN
        magic = struct.unpack_from("<I", img, off)[0]
        if magic == TSIG_MAGIC:
            return resign_tsig_image(img, key_index, seed)
    return img


# ---------------------------------------------------------------------------
# Headless Renode Harness
# ---------------------------------------------------------------------------

def reserve_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def dial_retry(port: int, timeout_s: float = 20.0) -> socket.socket:
    deadline = time.monotonic() + timeout_s
    last_err: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        except OSError as exc:
            last_err = exc
            time.sleep(0.05)
    raise TimeoutError(f"Timeout dialing 127.0.0.1:{port}: {last_err}")


class RenodeSession:
    def __init__(
        self,
        renode_bin: Path,
        work_dir: Path,
        resc_text: str,
        mon_port: int,
        uart_port: Optional[int],
        extra_env: Optional[Dict[str, str]] = None,
    ):
        self.work_dir = work_dir
        self.resc_path = work_dir / "run.resc"
        self.resc_path.write_text(resc_text, encoding="utf-8")
        self.uart_port = uart_port
        self.mon_port = mon_port

        self._uart_lock = threading.Lock()
        self._uart_buf = bytearray()
        self._mon_lock = threading.Lock()
        self._mon_buf = bytearray()
        self._stop_evt = threading.Event()

        proc_env = os.environ.copy()
        if extra_env:
            proc_env.update(extra_env)

        cmd = [str(renode_bin), "--disable-xwt", "--plain", "--port", str(mon_port), str(self.resc_path)]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(repo_root()),
            env=proc_env,
        )
        self.uart_sock: Optional[socket.socket] = None
        if uart_port is not None:
            self.uart_sock = dial_retry(uart_port, timeout_s=25.0)
            self._uart_thr = threading.Thread(target=self._reader, args=(self.uart_sock, self._uart_buf, self._uart_lock), daemon=True)
            self._uart_thr.start()
        self.mon_sock = dial_retry(mon_port, timeout_s=15.0)
        self._mon_thr = threading.Thread(target=self._reader, args=(self.mon_sock, self._mon_buf, self._mon_lock), daemon=True)
        self._mon_thr.start()

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if "(nrf52840_" in self.mon_snapshot():
                break
            time.sleep(0.025)

    def _reader(self, sock: socket.socket, buf: bytearray, lock: threading.Lock) -> None:
        sock.settimeout(0.25)
        while not self._stop_evt.is_set():
            try:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                with lock:
                    buf.extend(chunk)
            except socket.timeout:
                continue
            except OSError:
                return

    def start(self) -> None:
        self.exec_mon("start")

    def exec_mon(self, cmd_line: str) -> None:
        self.mon_sock.sendall((cmd_line + "\r\n").encode("utf-8"))

    def uart_snapshot(self) -> bytes:
        with self._uart_lock:
            return bytes(self._uart_buf)

    def mon_snapshot(self) -> str:
        with self._mon_lock:
            return self._mon_buf.decode("utf-8", errors="replace")

    def wait_uart_bytes(self, needle: bytes, timeout_s: float = 10.0, start_off: int = 0) -> int:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            snap = self.uart_snapshot()
            idx = snap.find(needle, start_off)
            if idx >= 0:
                return idx + len(needle)
            time.sleep(0.025)
        text = self.uart_snapshot().decode("utf-8", errors="replace")
        raise TimeoutError(f"Timed out waiting for UART {needle!r}; log:\n{text}")

    def wait_mon_text(self, needle: str, timeout_s: float = 8.0) -> str:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            snap = self.mon_snapshot()
            if needle in snap:
                return snap
            time.sleep(0.03)
        raise TimeoutError(f"Timed out waiting for Monitor {needle!r}; mon:\n{self.mon_snapshot()}")

    def read_cobs_frame(self, start_off: int, timeout_s: float = 6.0) -> Tuple[bytes, int]:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            snap = self.uart_snapshot()
            if start_off < len(snap):
                z = snap.find(0x00, start_off)
                if z >= 0:
                    raw = snap[start_off:z]
                    next_off = z + 1
                    if len(raw) == 0:
                        start_off = next_off
                        continue
                    out = bytearray()
                    i = 0
                    while i < len(raw):
                        code = raw[i]
                        if code == 0:
                            break
                        i += 1
                        end = i + code - 1
                        out.extend(raw[i:end])
                        i = end
                        if code < 0xFF and i < len(raw):
                            out.append(0)
                    return bytes(out), next_off
            time.sleep(0.02)
        raise TimeoutError("Timed out reading COBS frame from UART")

    def send_uart(self, data: bytes) -> None:
        if self.uart_sock is None:
            raise RuntimeError("UART socket not connected")
        self.uart_sock.sendall(data)

    def close(self) -> None:
        self._stop_evt.set()
        try:
            self.exec_mon("quit")
        except OSError:
            pass
        for s in (self.mon_sock, self.uart_sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        try:
            self.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2.0)


def make_base_resc(flash_path: Path, uicr_path: Path, uart_port: Optional[int], extra_lines: str = "") -> str:
    root = repo_root()
    overlay = (root / "test" / "renode_nrf52840" / "Nrf52840SocOverlay.cs").as_posix()
    repl = (root / "test" / "renode_nrf52840" / "nrf52840_toob.repl").as_posix()
    lines = [
        f"include @{overlay}",
        'mach create "nrf52840_fih"',
        f"machine LoadPlatformDescription @{repl}",
        "sysbus.nvmc InstallFlashHooks",
    ]
    if uart_port is not None:
        lines.append(f"emulation CreateServerSocketTerminal {uart_port} \"term\" false")
        lines.append("connector Connect sysbus.uart0 term")
    lines.extend([
        f"sysbus.flash LoadBinary @{flash_path.as_posix()} 0x0",
        f"sysbus.uicr LoadBinary @{uicr_path.as_posix()}",
        "",
        "macro reset",
        '"""',
        "    sysbus.cpu VectorTableOffset 0x0",
        "    sysbus.cpu SP `sysbus ReadDoubleWord 0x0`",
        "    sysbus.cpu PC `sysbus ReadDoubleWord 0x4`",
        '"""',
        "runMacro $reset",
    ])
    if extra_lines:
        lines.append(extra_lines)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Sub-runners: neg_e2e_vectors & probe_app_fault_test
# ---------------------------------------------------------------------------

def build_and_run_neg_e2e(work_dir: Path) -> None:
    work_dir.mkdir(parents=True, exist_ok=True)
    root = repo_root()
    clang = find_clang_bin()
    llvm_rt = Path(r"C:\Program Files\LLVM\lib\clang\22\lib\windows")
    env = os.environ.copy()
    env["TMP"] = str(work_dir)
    env["TEMP"] = str(work_dir)
    if llvm_rt.is_dir():
        env["PATH"] = f"{llvm_rt};{clang.parent};" + env.get("PATH", "")

    exe_path = work_dir / ("neg_e2e_vectors.exe" if os.name == "nt" else "neg_e2e_vectors")
    srcs = [
        root / "test" / "fih_emu" / "neg_e2e_vectors.c",
        root / "test" / "fuzz" / "fuzz_platform.c",
        root / "toobloader" / "core" / "boot_tbm1.c",
        root / "toobloader" / "core" / "boot_verify.c",
        root / "toobloader" / "core" / "boot_cloud_cmd.c",
        root / "toobloader" / "core" / "boot_journal.c",
        root / "toobloader" / "core" / "boot_rstore.c",
        root / "toobloader" / "core" / "boot_effect.c",
        root / "toobloader" / "core" / "boot_swap.c",
        root / "toobloader" / "core" / "utils" / "boot_crc32.c",
        root / "toobloader" / "core" / "utils" / "boot_identity.c",
        root / "toobloader" / "core" / "utils" / "boot_secure_zeroize_host.c",
    ]
    tp_srcs = [
        root / "toob-infra" / "registry" / "packages" / "crypto" / "backend" / "monocypher" / "monocypher.c",
        root / "toob-infra" / "registry" / "packages" / "crypto" / "backend" / "monocypher" / "monocypher-ed25519.c",
        root / "toob-infra" / "registry" / "packages" / "crypto" / "backend" / "monocypher" / "crypto_monocypher.c",
        root / "toob-infra" / "registry" / "packages" / "crypto" / "hash" / "sha256_sw" / "sha256.c",
        root / "toob-infra" / "registry" / "packages" / "crypto" / "hash" / "sha256_sw" / "crypto_sha256.c",
    ]
    incs = [
        f"-I{root / 'test' / 'fuzz'}",
        f"-I{root / 'test' / 'fuzz' / 'include'}",
        f"-I{root / 'common' / 'include'}",
        f"-I{root / 'common' / 'lib' / 'heatshrink'}",
        f"-I{root / 'toobloader' / 'core' / 'include'}",
        f"-I{root / 'toobloader' / 'core' / 'utils' / 'include'}",
        f"-I{root / 'sdk' / 'libtoob' / 'include'}",
        f"-I{root / 'toob-infra' / 'registry' / 'packages' / 'crypto' / 'backend' / 'monocypher'}",
        f"-I{root / 'toob-infra' / 'registry' / 'packages' / 'crypto' / 'hash' / 'sha256_sw'}",
    ]
    defs = [
        "-DHEATSHRINK_DYNAMIC_ALLOC=0",
        "-DHEATSHRINK_STATIC_INPUT_BUFFER_SIZE=128",
        "-DHEATSHRINK_STATIC_WINDOW_BITS=8",
        "-DHEATSHRINK_STATIC_LOOKAHEAD_BITS=4",
        "-DTOOB_PQC_ENABLED=1",
        "-DTOOB_TA1_STRICT_NO_CRC_SKIP=1",
        "-DTOOB_FEATURE_CLOUD_COMMANDS=1",
    ]
    if os.name == "nt":
        defs.append("-D_CRT_SECURE_NO_WARNINGS=1")

    tp_objs: List[Path] = []
    for tp in tp_srcs:
        obj = work_dir / f"{tp.stem}_tp.o"
        if not obj.is_file():
            subprocess.check_call(
                [str(clang), "-std=c17", "-O1", "-g", "-fsanitize=address,undefined", *incs, *defs, "-c", str(tp), "-o", str(obj)],
                env=env,
            )
        tp_objs.append(obj)

    subprocess.check_call(
        [
            str(clang),
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
            *incs,
            *defs,
            *(str(s) for s in srcs),
            *(str(o) for o in tp_objs),
            "-o",
            str(exe_path),
        ],
        env=env,
    )
    out = subprocess.check_output([str(exe_path)], env=env, text=True)
    for line in out.strip().splitlines():
        print(f"  {line}")
    if "NEG_E2E_SUMMARY passed=5/5 status=PASS" not in out:
        raise RuntimeError("neg_e2e_vectors did not report 5/5 PASS")


def build_probe_app(probe_out: Path) -> Path:
    script = repo_root() / "test" / "fih_emu" / "probe_app_fault_test" / "build_probe.ps1"
    subprocess.check_call([
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        "-OutDir",
        str(probe_out),
    ])
    toob_path = probe_out / "probe_app_fault_test.toob"
    if not toob_path.is_file():
        raise FileNotFoundError(f"Probe binary not produced: {toob_path}")
    return toob_path


# ---------------------------------------------------------------------------
# Provisioning, SRAM Audit, Probe App, Negative E2E & FIH Campaign (Renode)
# ---------------------------------------------------------------------------

def provision_baseline(renode_bin: Path, base_dir: Path) -> Tuple[Path, Path]:
    root = repo_root()
    build_dir = root / "test" / "renode_nrf52840" / "builds" / "build_nrf52840"
    apps_dir = root / "test" / "renode_nrf52840" / "builds" / "apps"

    stage0 = (build_dir / "toob_stage0.bin").read_bytes()
    stage1 = (build_dir / "toob_stage1.signed.bin").read_bytes()
    recovery = maybe_resign_tsig_image((build_dir / "toob_recovery.bin").read_bytes(), 1)
    app_v1 = maybe_resign_tsig_image((apps_dir / "app_v1.toob").read_bytes(), 1)
    root_pk = ed25519_public_from_seed(ROOT_SEED)

    flash = bytearray(b"\xFF" * FLASH_TOTAL_SIZE)
    flash[OFF_STAGE0 : OFF_STAGE0 + len(stage0)] = stage0
    flash[OFF_STAGE1A : OFF_STAGE1A + len(stage1)] = stage1
    flash[OFF_RECOVERY : OFF_RECOVERY + len(recovery)] = recovery
    flash[OFF_APP_SLOT0 : OFF_APP_SLOT0 + len(app_v1)] = app_v1

    uicr = bytearray(b"\xFF" * UICR_TOTAL_SIZE)
    uicr[UICR_OFF_KEY0 : UICR_OFF_KEY0 + 32] = root_pk

    prov_work = base_dir / "prov_work"
    prov_work.mkdir(parents=True, exist_ok=True)
    flash_in = prov_work / "flash_in.bin"
    uicr_in = prov_work / "uicr_in.bin"
    flash_in.write_bytes(flash)
    uicr_in.write_bytes(uicr)

    flash_out = base_dir / "provisioned_flash.bin"
    uicr_out = base_dir / "provisioned_uicr.bin"
    mon_port = reserve_free_port()
    uart_port = reserve_free_port()
    resc = make_base_resc(flash_in, uicr_in, uart_port)

    sess = RenodeSession(renode_bin, prov_work, resc, mon_port, uart_port)
    try:
        sess.start()
        off = sess.wait_uart_bytes(b"[S0] Signature verification PASSED!", timeout_s=10.0)
        off = sess.wait_uart_bytes(cobs_encode(b"PROV"), timeout_s=8.0, start_off=off)

        for cmd_bytes in [
            build_prov_frame(PROV_CMD_BURN_KEY, bytes([1]) + root_pk),
            build_prov_frame(PROV_CMD_LOCK_BOOT_FLASH),
            build_prov_frame(PROV_CMD_SET_DSLC, bytes([0x01])),
            build_prov_frame(PROV_CMD_REBOOT),
        ]:
            sess.send_uart(cmd_bytes)
            frame, off = sess.read_cobs_frame(off, timeout_s=6.0)
            if len(frame) != 4 or struct.unpack("<I", frame)[0] != BOOT_OK_U32:
                raise RuntimeError(f"Provisioning step returned status {frame.hex()}")

        sess.wait_uart_bytes(b"[APP] BOOT ver=1.0.0 slot=0 tent=0 handoff=OK", timeout_s=12.0, start_off=off)
        sess.exec_mon("pause")
        sess.exec_mon(
            f'python "import System.IO; sb = emulationManager.CurrentEmulation.Machines[0].SystemBus; '
            f'data = sb.ReadBytes(0x0, 0x100000); '
            f'System.IO.File.WriteAllBytes(\'{flash_out.as_posix()}\', data)"'
        )
        sess.exec_mon(f"sysbus.uicr SaveBinary @{uicr_out.as_posix()}")
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and (not flash_out.is_file() or not uicr_out.is_file()):
            time.sleep(0.05)
        if not flash_out.is_file() or not uicr_out.is_file():
            raise RuntimeError(f"Failed saving provisioned flash/uicr; mon=\n{sess.mon_snapshot()}")
    finally:
        sess.close()

    print(f"TIER2_PROVISIONING status=PASS flash={flash_out} uicr={uicr_out}")
    return flash_out, uicr_out


def run_sram_handover_audit(
    renode_bin: Path,
    base_dir: Path,
    flash_prov: Path,
    uicr_prov: Path,
    syms_s1: Dict[str, Tuple[int, int]],
) -> Tuple[bool, List[str]]:
    if "jump_to_vtor_image" not in syms_s1:
        raise RuntimeError("Missing symbol jump_to_vtor_image in toob_stage1")
    handoff_pc = syms_s1["jump_to_vtor_image"][0]
    audit_dir = base_dir / "sram_audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    dump_bin = audit_dir / "sram_handover_dump.bin"
    if dump_bin.exists():
        dump_bin.unlink()

    root = repo_root()
    template_resc = (root / "test" / "fih_emu" / "sram_handover_audit.resc").as_posix()
    mon_port = reserve_free_port()
    uart_port = reserve_free_port()

    resc = "\n".join([
        f"$OVERLAY_CS=@{(root / 'test' / 'renode_nrf52840' / 'Nrf52840SocOverlay.cs').as_posix()}",
        f"$REPL_PATH=@{(root / 'test' / 'renode_nrf52840' / 'nrf52840_toob.repl').as_posix()}",
        f"$FLASH_BIN=@{flash_prov.as_posix()}",
        f"$UICR_BIN=@{uicr_prov.as_posix()}",
        f"$AUDIT_OUT_PATH=\"{dump_bin.as_posix()}\"",
        f"$HANDOFF_PC=0x{handoff_pc:08x}",
        f"$UART_PORT={uart_port}",
        f"include @{template_resc}",
    ]) + "\n"

    sess = RenodeSession(
        renode_bin,
        audit_dir,
        resc,
        mon_port,
        uart_port,
        extra_env={"TOOB_SRAM_AUDIT_OUT": dump_bin.as_posix()},
    )
    try:
        sess.start()
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and not dump_bin.is_file():
            time.sleep(0.04)
        if not dump_bin.is_file():
            raise RuntimeError(f"SRAM audit dump file was not written; mon=\n{sess.mon_snapshot()}")
        time.sleep(0.05)
    finally:
        sess.close()

    sram = dump_bin.read_bytes()
    if len(sram) != 0x40000:
        raise RuntimeError(f"Unexpected SRAM dump size {len(sram)} != 0x40000")

    findings: List[str] = []
    sram_base = 0x20000000
    arena_addr, arena_sz = syms_s1.get("crypto_arena", (0x20000010, 4096))
    if arena_sz == 0:
        arena_sz = 4096
    arena_off = arena_addr - sram_base
    arena_nonzero = sum(1 for b in sram[arena_off : arena_off + arena_sz] if b != 0)
    if arena_nonzero != 0:
        findings.append(f"crypto_arena_nonzero={arena_nonzero}")

    jk_nonzero = 0
    if "journal_key" in syms_s1:
        jk_addr, jk_sz = syms_s1["journal_key"]
        if jk_sz == 0:
            jk_sz = 16
        jk_off = jk_addr - sram_base
        jk_bytes = sram[jk_off : jk_off + jk_sz]
        jk_nonzero = sum(1 for b in jk_bytes if b != 0)
        if jk_nonzero != 0:
            has_zeroize_sym = "boot_journal_zeroize_secrets" in syms_s1
            findings.append(
                f"journal_key_nonzero={jk_nonzero} (boot_journal_zeroize_secrets_in_elf={has_zeroize_sym})"
            )
            stack_copy_off = sram.find(jk_bytes, 0x30000)
            if stack_copy_off >= 0:
                findings.append(f"journal_key_stack_residual_at=0x{sram_base + stack_copy_off:08x}")

    jkv_val = 0
    if "journal_key_valid" in syms_s1:
        jkv_off = syms_s1["journal_key_valid"][0] - sram_base
        jkv_val = sram[jkv_off]
        if jkv_val != 0:
            findings.append(f"journal_key_valid={jkv_val}")

    domain_leaks = 0
    for forbidden in (b"toob-journal-key-v2",):
        if forbidden in sram:
            domain_leaks += 1
            findings.append(f"domain_literal_leak={forbidden!r}")

    ok = len(findings) == 0
    status = "PASS" if ok else "FAIL"
    print(
        f"TIER2_SRAM_AUDIT handoff_pc=0x{handoff_pc:08x} crypto_arena_nonzero={arena_nonzero} "
        f"journal_key_nonzero={jk_nonzero} journal_key_valid={jkv_val} "
        f"domain_leaks={domain_leaks} status={status}"
    )
    for f in findings:
        print(f"  SRAM_AUDIT_FINDING: {f}")
    return ok, findings


def run_probe_app_in_renode(renode_bin: Path, base_dir: Path, flash_prov: Path, uicr_prov: Path, probe_raw_toob: Path) -> None:
    probe_dir = base_dir / "probe_run"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_signed = maybe_resign_tsig_image(probe_raw_toob.read_bytes(), 1)

    flash = bytearray(flash_prov.read_bytes())
    flash[OFF_APP_SLOT0 : OFF_APP_SLOT0 + 0x30000] = b"\xFF" * 0x30000
    flash[OFF_APP_SLOT0 : OFF_APP_SLOT0 + len(probe_signed)] = probe_signed
    flash_p = probe_dir / "flash_probe.bin"
    flash_p.write_bytes(flash)

    mon_port = reserve_free_port()
    uart_port = reserve_free_port()
    resc = make_base_resc(flash_p, uicr_prov, uart_port)
    sess = RenodeSession(renode_bin, probe_dir, resc, mon_port, uart_port)
    try:
        sess.start()
        off = sess.wait_uart_bytes(b"[PROBE] BOOT slot=0 handoff=OK confirm=OK", timeout_s=12.0)
        off = sess.wait_uart_bytes(b"[PROBE] DONE", timeout_s=8.0, start_off=off)
        uart_text = sess.uart_snapshot().decode("utf-8", errors="replace")
        if "sticky=OK" not in uart_text or "status=PROTECTED" not in uart_text:
            raise RuntimeError(f"Probe App hardware lockdown check failed!\nUART:\n{uart_text}")
        sess.exec_mon("pause")
        sess.exec_mon("sysbus.powerBprot BlockedOperations")
        mon_out = sess.wait_mon_text("BlockedOperations", timeout_s=4.0)
        m = re.search(r"BlockedOperations\s*[\r\n]+(0x[0-9a-fA-F]+|\d+)", mon_out)
        blocked_cnt = int(m.group(1), 0) if m else -1
        if blocked_cnt < 2:
            raise RuntimeError(f"Expected powerBprot.BlockedOperations >= 2 (erase+write), got {blocked_cnt}\nmon:\n{mon_out}")
        for line in uart_text.splitlines():
            if "[PROBE]" in line:
                print(f"  {line.strip()}")
        print(f"TIER2_PROBE_APP bprot_blocked_ops={blocked_cnt} status=PASS")
    finally:
        sess.close()


def run_single_renode_expect_deny(
    renode_bin: Path,
    work_dir: Path,
    flash_bytes: bytes,
    uicr_bytes: bytes,
    label: str,
    forbidden_substrings: Tuple[bytes, ...],
    extra_mon_lines: str = "",
    run_secs: float = 1.6,
    require_mon_marker: Optional[str] = None,
) -> None:
    work_dir.mkdir(parents=True, exist_ok=True)
    fp = work_dir / "flash.bin"
    up = work_dir / "uicr.bin"
    fp.write_bytes(flash_bytes)
    up.write_bytes(uicr_bytes)

    mon_port = reserve_free_port()
    uart_port = reserve_free_port()
    resc = make_base_resc(fp, up, uart_port, extra_mon_lines)
    sess = RenodeSession(renode_bin, work_dir, resc, mon_port, uart_port)
    try:
        sess.start()
        time.sleep(run_secs)
        snap = sess.uart_snapshot()
        mon_snap = sess.mon_snapshot()
    finally:
        sess.close()

    for bad in forbidden_substrings:
        if bad in snap:
            text = snap.decode("utf-8", errors="replace")
            raise RuntimeError(f"SECURITY FAILURE ({label}): forbidden UART marker {bad!r} appeared!\n{text}")
    if require_mon_marker and require_mon_marker not in mon_snap:
        # Check CPU PC via file marker if used
        marker_file = work_dir / "fih_hit.txt"
        if not marker_file.is_file():
            raise RuntimeError(f"Fault hook did not trigger for {label}! mon=\n{mon_snap}")


def run_live_renode_negative_e2e(
    renode_bin: Path,
    base_dir: Path,
    flash_prov: Path,
    uicr_prov: Path,
    probe_raw_toob: Path,
) -> Tuple[bool, List[str]]:
    prov_flash = bytearray(flash_prov.read_bytes())
    prov_uicr = uicr_prov.read_bytes()
    root = repo_root()
    raw_probe = base_dir / "probe_app" / "probe_app_fault_test.raw.bin"
    if not raw_probe.is_file():
        raw_probe = probe_raw_toob.with_name("probe_app_fault_test.raw.bin")

    failures: List[str] = []

    def check_case(case_id: str, work: Path, flash_b: bytes, uicr_b: bytes, label: str, forbidden: Tuple[bytes, ...]) -> None:
        try:
            run_single_renode_expect_deny(renode_bin, work, flash_b, uicr_b, label, forbidden, run_secs=1.5)
            print(f"  RENODE_NEG_E2E id={case_id} status=PASS")
        except RuntimeError as exc:
            first_line = str(exc).splitlines()[0]
            print(f"  RENODE_NEG_E2E id={case_id} status=FAIL reason={first_line}")
            failures.append(f"{case_id}: {first_line}")

    # 1. Blank 0xFF UICR -> Stage 0 fail-closed
    check_case(
        "blank_uicr",
        base_dir / "neg_live_blank_uicr",
        bytes(prov_flash),
        b"\xFF" * UICR_TOTAL_SIZE,
        "RENODE-NEG-BLANK-UICR",
        (b"[APP] BOOT", b"[PROBE] BOOT", b"[S0] Signature verification PASSED!"),
    )

    # 2. Deployed (DSLC=0x01) + blank 0xFF WAL -> Stage 1 fail-closed
    f_blank_wal = bytearray(prov_flash)
    f_blank_wal[OFF_WAL : OFF_WAL + WAL_SIZE] = b"\xFF" * WAL_SIZE
    check_case(
        "deployed_blank_wal",
        base_dir / "neg_live_deployed_blank_wal",
        bytes(f_blank_wal),
        prov_uicr,
        "RENODE-NEG-DEPLOYED-BLANK-WAL",
        (b"[APP] BOOT", b"[PROBE] BOOT"),
    )

    # 3. Unsigned App image -> Stage 1 rejects TSIG / TOOB header missing
    f_unsigned = bytearray(prov_flash)
    f_unsigned[OFF_APP_SLOT0 : OFF_APP_SLOT0 + 0x30000] = b"\xFF" * 0x30000
    raw_bytes = raw_probe.read_bytes()
    f_unsigned[OFF_APP_SLOT0 : OFF_APP_SLOT0 + len(raw_bytes)] = raw_bytes
    check_case(
        "unsigned_app",
        base_dir / "neg_live_unsigned_app",
        bytes(f_unsigned),
        prov_uicr,
        "RENODE-NEG-UNSIGNED-APP",
        (b"[APP] BOOT", b"[PROBE] BOOT"),
    )

    # 4. Tampered App Slot 0 header / TSIG -> Stage 1 rejects
    f_bad_tsig = bytearray(prov_flash)
    app_v1_signed = maybe_resign_tsig_image((root / "test" / "renode_nrf52840" / "builds" / "apps" / "app_v1.toob").read_bytes(), 1)
    bad_tsig = bytearray(app_v1_signed)
    if len(bad_tsig) >= 20 + TSIG_TRAILER_LEN and struct.unpack_from("<I", bad_tsig, len(bad_tsig) - TSIG_TRAILER_LEN)[0] == TSIG_MAGIC:
        bad_tsig[len(bad_tsig) - 10] ^= 0x01
    else:
        bad_tsig[0] ^= 0x01
    f_bad_tsig[OFF_APP_SLOT0 : OFF_APP_SLOT0 + 0x30000] = b"\xFF" * 0x30000
    f_bad_tsig[OFF_APP_SLOT0 : OFF_APP_SLOT0 + len(bad_tsig)] = bad_tsig
    check_case(
        "tampered_app_image",
        base_dir / "neg_live_tampered_tsig",
        bytes(f_bad_tsig),
        prov_uicr,
        "RENODE-NEG-TAMPERED-APP",
        (b"[APP] BOOT", b"[PROBE] BOOT"),
    )

    # 5. Tampered Stage 1A image -> Stage 0 rejects, never passes verify
    f_bad_s1 = bytearray(prov_flash)
    f_bad_s1[OFF_STAGE1A + 0x200] ^= 0x01
    f_bad_s1[OFF_STAGE1B : OFF_STAGE1B + 0x18000] = b"\xFF" * 0x18000
    check_case(
        "tampered_stage1a",
        base_dir / "neg_live_tampered_stage1",
        bytes(f_bad_s1),
        prov_uicr,
        "RENODE-NEG-TAMPERED-STAGE1A",
        (b"[S0] Signature verification PASSED!", b"[APP] BOOT"),
    )

    return len(failures) == 0, failures


def build_fih_hook_script(run_dir: Path, hit_file: Path, site: InsnSite, fault_mode: str) -> str:
    hit_path = hit_file.as_posix()
    hook_py = run_dir / "fih_hook.py"

    if fault_mode == "single_skip":
        action_lines = [
            f"    cpu.PC = RegisterValue.Create(0x{site.pc + site.width:x}, 32)"
        ]
    elif fault_mode == "double_skip":
        action_lines = [
            f"    cpu.PC = RegisterValue.Create(0x{site.pc + site.width + site.next_width:x}, 32)"
        ]
    elif fault_mode == "reg_r0_boot_ok":
        action_lines = [
            "    cpu.SetRegister(0, RegisterValue.Create(0x55AA55AA, 32))"
        ]
    elif fault_mode == "reg_r0_flip":
        action_lines = [
            "    v = cpu.GetRegister(0).RawValue ^ 1",
            "    cpu.SetRegister(0, RegisterValue.Create(v & 0xFFFFFFFF, 32))",
        ]
    elif fault_mode == "reg_r1_r3_flip":
        action_lines = [
            "    for r in (1, 2, 3):",
            "        rv = cpu.GetRegister(r).RawValue ^ 0xFFFFFFFF",
            "        cpu.SetRegister(r, RegisterValue.Create(rv & 0xFFFFFFFF, 32))",
        ]
    else:
        raise ValueError(f"Unknown fault_mode: {fault_mode}")

    py_lines = [
        "import sys, System.IO",
        "from Antmicro.Renode.Peripherals.CPU import RegisterValue",
        "sys._toob_fih_done = False",
        "def _toob_fih_cb(cpu, cur_pc):",
        "    if sys._toob_fih_done:",
        "        return",
        "    sys._toob_fih_done = True",
        f"    System.IO.File.WriteAllText('{hit_path}', 'HIT 0x%08x {fault_mode}\\n' % int(cur_pc))",
        *action_lines,
        "sys._toob_fih_cb = _toob_fih_cb",
    ]
    hook_py.write_text("\n".join(py_lines) + "\n", encoding="utf-8")

    return (
        f'python "import sys; exec(open(\'{hook_py.as_posix()}\').read(), sys.__dict__)"\n'
        f'sysbus.cpu AddHook 0x{site.pc:08x} "import sys; sys._toob_fih_cb(self, pc)"'
    )


def trace_reachable_sites(
    renode_bin: Path,
    trace_dir: Path,
    flash_bytes: bytes,
    uicr_bytes: bytes,
    sites: List[InsnSite],
    run_secs: float = 1.4,
) -> List[InsnSite]:
    if trace_dir.exists():
        shutil.rmtree(trace_dir)
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_file = trace_dir / "reached_pcs.txt"
    trace_py = trace_dir / "trace_hook.py"

    trace_py.write_text(
        "\n".join([
            "import sys, System.IO",
            "sys._toob_seen = set()",
            "def _toob_trace_cb(cur_pc):",
            "    k = int(cur_pc)",
            "    if k not in sys._toob_seen:",
            "        sys._toob_seen.add(k)",
            f"        System.IO.File.AppendAllText('{trace_file.as_posix()}', ('0x%08x\\n' % k))",
            "sys._toob_trace_cb = _toob_trace_cb",
        ]) + "\n",
        encoding="utf-8",
    )

    hook_lines = [
        f'python "import sys; exec(open(\'{trace_py.as_posix()}\').read(), sys.__dict__)"'
    ]
    seen_add = set()
    for s in sites:
        if s.pc in seen_add:
            continue
        seen_add.add(s.pc)
        hook_lines.append(f'sysbus.cpu AddHook 0x{s.pc:08x} "import sys; sys._toob_trace_cb(pc)"')

    fp = trace_dir / "flash.bin"
    up = trace_dir / "uicr.bin"
    fp.write_bytes(flash_bytes)
    up.write_bytes(uicr_bytes)
    mon_port = reserve_free_port()
    uart_port = reserve_free_port()
    resc = make_base_resc(fp, up, uart_port, "\n".join(hook_lines))
    sess = RenodeSession(renode_bin, trace_dir, resc, mon_port, uart_port)
    try:
        sess.start()
        time.sleep(run_secs)
    finally:
        sess.close()

    reached = set()
    if trace_file.is_file():
        for line in trace_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                reached.add(int(line, 16))
    return [s for s in sites if s.pc in reached]


def run_fih_campaign(
    renode_bin: Path,
    base_dir: Path,
    flash_prov: Path,
    uicr_prov: Path,
    s0_sites: List[InsnSite],
    s1_sites: List[InsnSite],
    max_targets_per_stage: int,
) -> None:
    prov_flash = bytearray(flash_prov.read_bytes())
    prov_uicr = uicr_prov.read_bytes()

    # Stage 0 tampered image (bit flip in Stage 1A + blank Stage 1B)
    f_bad_s1 = bytearray(prov_flash)
    f_bad_s1[OFF_STAGE1A + 0x200] ^= 0x01
    f_bad_s1[OFF_STAGE1B : OFF_STAGE1B + 0x18000] = b"\xFF" * 0x18000

    # Stage 1 tampered App image (1-bit TSIG flip or corrupted header in App Slot 0)
    app_v1_signed = maybe_resign_tsig_image(
        (repo_root() / "test" / "renode_nrf52840" / "builds" / "apps" / "app_v1.toob").read_bytes(), 1
    )
    bad_tsig = bytearray(app_v1_signed)
    if len(bad_tsig) >= 20 + TSIG_TRAILER_LEN and struct.unpack_from("<I", bad_tsig, len(bad_tsig) - TSIG_TRAILER_LEN)[0] == TSIG_MAGIC:
        bad_tsig[len(bad_tsig) - 10] ^= 0x01
    else:
        bad_tsig[0] ^= 0x01
    f_bad_app = bytearray(prov_flash)
    f_bad_app[OFF_APP_SLOT0 : OFF_APP_SLOT0 + 0x30000] = b"\xFF" * 0x30000
    f_bad_app[OFF_APP_SLOT0 : OFF_APP_SLOT0 + len(bad_tsig)] = bad_tsig

    s0_exec = trace_reachable_sites(renode_bin, base_dir / "trace_s0", bytes(f_bad_s1), prov_uicr, s0_sites)
    s1_exec = trace_reachable_sites(renode_bin, base_dir / "trace_s1", bytes(f_bad_app), prov_uicr, s1_sites)

    def pick_representative(sites: List[InsnSite], cap: int) -> List[InsnSite]:
        gates = [s for s in sites if s.kind == "glitch_gate"]
        calls = [s for s in sites if s.kind == "call_check"]
        cmps = [s for s in sites if s.kind == "branch_cmp"]
        chosen: List[InsnSite] = []
        for group in (gates, calls, cmps):
            for s in group:
                if len(chosen) >= cap:
                    break
                chosen.append(s)
        return chosen

    s0_pick = pick_representative(s0_exec, max_targets_per_stage)
    s1_pick = pick_representative(s1_exec, max_targets_per_stage)
    if not s0_pick or not s1_pick:
        raise RuntimeError(f"Insufficient reachable FIH targets (s0={len(s0_pick)}, s1={len(s1_pick)})")

    fault_modes = ("single_skip", "double_skip", "reg_r0_boot_ok", "reg_r0_flip", "reg_r1_r3_flip")
    total_runs = 0
    s0_hits = 0
    s1_hits = 0

    for idx, site in enumerate(s0_pick):
        mode = fault_modes[idx % len(fault_modes)]
        run_dir = base_dir / f"fih_s0_{idx:02d}_{mode}"
        if run_dir.exists():
            shutil.rmtree(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        hit_file = run_dir / "fih_hit.txt"
        hook_cmd = build_fih_hook_script(run_dir, hit_file, site, mode)
        run_single_renode_expect_deny(
            renode_bin,
            run_dir,
            bytes(f_bad_s1),
            prov_uicr,
            f"FIH-S0-{site.function}@0x{site.pc:08x}-{mode}",
            (b"[S0] Signature verification PASSED!", b"[APP] BOOT"),
            extra_mon_lines=hook_cmd,
            run_secs=1.2,
            require_mon_marker=None,
        )
        total_runs += 1
        if hit_file.is_file():
            s0_hits += 1

    for idx, site in enumerate(s1_pick):
        mode = fault_modes[idx % len(fault_modes)]
        run_dir = base_dir / f"fih_s1_{idx:02d}_{mode}"
        if run_dir.exists():
            shutil.rmtree(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        hit_file = run_dir / "fih_hit.txt"
        hook_cmd = build_fih_hook_script(run_dir, hit_file, site, mode)
        run_single_renode_expect_deny(
            renode_bin,
            run_dir,
            bytes(f_bad_app),
            prov_uicr,
            f"FIH-S1-{site.function}@0x{site.pc:08x}-{mode}",
            (b"[APP] BOOT", b"[PROBE] BOOT"),
            extra_mon_lines=hook_cmd,
            run_secs=1.2,
            require_mon_marker=None,
        )
        total_runs += 1
        if hit_file.is_file():
            s1_hits += 1

    hits_confirmed = s0_hits + s1_hits
    if s0_hits != len(s0_pick) or s1_hits != len(s1_pick):
        raise RuntimeError(
            f"FIH Campaign hook reachability mismatch: s0={s0_hits}/{len(s0_pick)}, s1={s1_hits}/{len(s1_pick)}"
        )

    print(
        f"TIER2_FIH_CAMPAIGN reachable_s0={len(s0_exec)} reachable_s1={len(s1_exec)} "
        f"faults_injected={total_runs} hooks_hit={hits_confirmed}/{total_runs} "
        f"bypasses=0 status=PASS"
    )


# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Toob-Loader Tier 2 FIH & Negative E2E Harness")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", help="Run ELF analysis, script validation, probe build, and C neg_e2e_vectors")
    group.add_argument("--full", action="store_true", help="Run --dry-run plus live Renode FIH campaign, SRAM audit, BPROT probe, and negative E2E")
    parser.add_argument("--work-dir", default=r"D:\ToobStorage\tmp_build\w2sec\fih_emu", help="Working/output directory")
    parser.add_argument("--max-targets", type=int, default=6, help="Max fault sites per stage in --full campaign")
    args = parser.parse_args()

    verify_ed25519_rfc8032_selftest()

    root = repo_root()
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    nm_bin = find_arm_tool("arm-none-eabi-nm.exe" if os.name == "nt" else "arm-none-eabi-nm")
    objdump_bin = find_arm_tool("arm-none-eabi-objdump.exe" if os.name == "nt" else "arm-none-eabi-objdump")

    elf_s0 = root / "test" / "renode_nrf52840" / "builds" / "build_nrf52840" / "toob_stage0"
    elf_s1 = root / "test" / "renode_nrf52840" / "builds" / "build_nrf52840" / "toob_stage1"
    if not elf_s0.is_file() or not elf_s1.is_file():
        raise FileNotFoundError(f"Missing nRF52840 ELFs under {elf_s0.parent}")

    syms_s0 = parse_nm_symbols(nm_bin, elf_s0)
    syms_s1 = parse_nm_symbols(nm_bin, elf_s1)

    s0_sites, s0_gates = parse_disassembly_targets(
        objdump_bin, elf_s0, "stage0", ("stage0_verify_signature", "stage0_try_boot_bank")
    )
    s1_sites, s1_gates = parse_disassembly_targets(
        objdump_bin,
        elf_s1,
        "stage1",
        ("boot_verify_slot_image", "boot_state_run", "boot_verify_manifest_envelope", "stage_verify_envelope", "enforce_dslc_lifecycle"),
    )

    if not s0_sites or not s1_sites:
        raise RuntimeError(f"Failed discovering FIH targets (s0={len(s0_sites)}, s1={len(s1_sites)})")

    audit_resc = root / "test" / "fih_emu" / "sram_handover_audit.resc"
    resc_text = audit_resc.read_text(encoding="utf-8")
    if "$HANDOFF_PC" not in resc_text or "AddHook" not in resc_text:
        raise RuntimeError("Invalid sram_handover_audit.resc")

    vec_json = root / "test" / "fih_emu" / "negative_e2e_vectors.json"
    vec_data = json.loads(vec_json.read_text(encoding="utf-8"))
    if len(vec_data.get("scenarios", [])) < 5:
        raise RuntimeError("Expected at least 5 scenarios in negative_e2e_vectors.json")

    print(
        f"TIER2_ELF_DISCOVERY stage0_sites={len(s0_sites)} (glitch_gates={len(s0_gates)}) "
        f"stage1_sites={len(s1_sites)} (glitch_gates={len(s1_gates)}) "
        f"sram_audit_pc=0x{syms_s1['jump_to_vtor_image'][0]:08x}"
    )

    probe_toob = build_probe_app(work_dir / "probe_app")
    build_and_run_neg_e2e(work_dir / "neg_e2e")

    if not args.full:
        print("TIER2_SMOKE_SUMMARY status=PASS")
        return 0

    renode_bin = find_renode_bin()
    if renode_bin is None:
        raise FileNotFoundError("Renode binary not found; cannot run --full Tier 2 campaign")

    flash_prov, uicr_prov = provision_baseline(renode_bin, work_dir)
    sram_audit_ok, sram_findings = run_sram_handover_audit(renode_bin, work_dir, flash_prov, uicr_prov, syms_s1)
    run_probe_app_in_renode(renode_bin, work_dir, flash_prov, uicr_prov, probe_toob)
    neg_live_ok, neg_live_findings = run_live_renode_negative_e2e(renode_bin, work_dir, flash_prov, uicr_prov, probe_toob)
    run_fih_campaign(renode_bin, work_dir, flash_prov, uicr_prov, s0_sites, s1_sites, args.max_targets)

    all_findings = sram_findings + neg_live_findings
    if not sram_audit_ok or not neg_live_ok:
        print(f"TIER2_FULL_SUMMARY status=FAIL findings={'; '.join(all_findings)}")
        return 1

    print("TIER2_FULL_SUMMARY status=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
