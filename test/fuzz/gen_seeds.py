#!/usr/bin/env python3
"""Deterministic valid + adversarial seed corpus generator for Toob-Loader Tier 1 fuzzers."""

import hashlib
import os
import struct
import zlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CORPUS_ROOT = os.path.join(SCRIPT_DIR, "corpus")

# ---- Pure-Python RFC 8032 Ed25519 Signer (Zero External Dependencies) ----
_ED_Q = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, -1, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, -1, _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ED_I) % _ED_Q
    if x % 2 != 0:
        x = _ED_Q - x
    return x


_ED_BY = 4 * pow(5, -1, _ED_Q) % _ED_Q
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX % _ED_Q, _ED_BY % _ED_Q)


def _ed_point_add(p, q):
    x1, y1 = p
    x2, y2 = q
    dx = _ED_D * x1 * x2 * y1 * y2 % _ED_Q
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + dx, -1, _ED_Q)) % _ED_Q
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - dx, -1, _ED_Q)) % _ED_Q
    return (x3, y3)


def _ed_scalarmult(p, e: int):
    q = (0, 1)
    cur = p
    while e > 0:
        if e & 1:
            q = _ed_point_add(q, cur)
        cur = _ed_point_add(cur, cur)
        e >>= 1
    return q


def _ed_encode_point(p) -> bytes:
    x, y = p
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _ed_keypair(seed32: bytes):
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pk = _ed_encode_point(_ed_scalarmult(_ED_B, a))
    return seed32, pk


def _ed_sign(seed32: bytes, pk: bytes, msg: bytes) -> bytes:
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:64]
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _ED_L
    r_pt = _ed_encode_point(_ed_scalarmult(_ED_B, r))
    k = int.from_bytes(hashlib.sha512(r_pt + pk + msg).digest(), "little") % _ED_L
    s = (r + k * a) % _ED_L
    return r_pt + s.to_bytes(32, "little")


ROOT_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
CLOUD_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
_, ROOT_PK = _ed_keypair(ROOT_SEED)
_, CLOUD_PK = _ed_keypair(CLOUD_SEED)

CHIP_UID = bytes([0x52, 0x84, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF])
DEVICE_SECRET = bytes(0x3A + i for i in range(32))
DEVICE_ID = hashlib.sha256(CHIP_UID + ROOT_PK + b"toob-device-id-v1").digest()
JOURNAL_KEY = hashlib.sha256(DEVICE_SECRET + CHIP_UID + ROOT_PK + b"toob-journal-key-v2").digest()[:16]


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def crc16_ccitt(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


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
    out.append(0)
    return bytes(out)


def write_seed(corpus: str, name: str, data: bytes) -> None:
    d = os.path.join(CORPUS_ROOT, corpus)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def build_tbm1_header(
    total_len: int,
    flags_crit: int = 0,
    vendor_id: int = 0x1915,
    product_id: int = 0x5284,
    hw_min: int = 1,
    hw_max: int = 1,
    key_index: int = 0,
    image_count: int = 1,
    min_rmaj: int = 2,
    min_rmin: int = 1,
    svn: int = 1,
    regions=None,
    images=None,
    fix_crc: bool = True,
) -> bytearray:
    buf = bytearray(512)
    struct.pack_into(
        "<IBBHIIHH",
        buf,
        0,
        0x314D4254,
        2,
        1,
        512,
        total_len,
        flags_crit,
        0,
        vendor_id,
    )
    struct.pack_into(
        "<HHHBBHHHH",
        buf,
        18,
        product_id,
        hw_min,
        hw_max,
        key_index,
        image_count,
        3,
        min_rmaj,
        min_rmin,
        0,
    )
    struct.pack_into("<IIIIHHHH", buf, 32, svn, 0, 0, 1, 1, 0, 0, 0)
    if regions:
        for i, (rid, off, rlen) in enumerate(regions[:8]):
            struct.pack_into("<HHII", buf, 88 + i * 12, rid, 0, off, rlen)
    if images:
        for i, img in enumerate(images[:4]):
            struct.pack_into(
                "<BBBBIIIIIIHHHH8s",
                buf,
                184 + i * 44,
                img.get("type", 0),
                img.get("slot", 0),
                img.get("comp", 0),
                img.get("delta", 0),
                img.get("data_off", 0),
                img.get("stored", 4096),
                img.get("installed", 4096),
                img.get("chunk_sz", 4096),
                img.get("num_chunks", 1),
                img.get("base_svn", 0),
                1,
                0,
                0,
                0,
                b"\x00" * 8,
            )
    if fix_crc:
        struct.pack_into("<I", buf, 508, crc32(bytes(buf[:508])))
    return buf


def gen_tbm1() -> None:
    # 1. Valid single-image TBM1 with chunk hashes and Ed25519 signature
    total_len = 512 + 32 + 64
    hdr = build_tbm1_header(
        total_len=total_len,
        regions=[(1, 512, 32)],
        images=[{"slot": 0, "data_off": 1024, "stored": 4096, "installed": 4096, "chunk_sz": 4096, "num_chunks": 1}],
    )
    chunk_hash = hashlib.sha256(b"A" * 4096).digest()
    body = bytes(hdr) + chunk_hash
    sig = _ed_sign(ROOT_SEED, ROOT_PK, body)
    write_seed("tbm1", "valid_head_single.bin", body + sig)

    # 2. Valid TBM1 with REVERSE_DELTA descriptor
    total_len_rd = 512 + 32 + 48 + 64
    hdr_rd = build_tbm1_header(
        total_len=total_len_rd,
        regions=[(1, 512, 32), (6, 544, 48)],
        images=[{"slot": 0, "data_off": 1024, "stored": 2048, "installed": 4096, "chunk_sz": 4096, "num_chunks": 1}],
    )
    rdelta = struct.pack("<BBHIII32s", 0, 3, 0, 3072, 512, 4096, hashlib.sha256(b"old").digest())
    body_rd = bytes(hdr_rd) + chunk_hash + rdelta
    write_seed("tbm1", "valid_rdelta.bin", body_rd + _ed_sign(ROOT_SEED, ROOT_PK, body_rd))

    # 3. Adversarial integer overflow in num_chunks / stored_size
    adv1 = build_tbm1_header(
        total_len=512 + 32 + 64,
        regions=[(1, 512, 32)],
        images=[{"slot": 0, "data_off": 0xFFFFF000, "stored": 0x2000, "installed": 0xFFFFFFFF, "chunk_sz": 4096, "num_chunks": 0}],
    )
    write_seed("tbm1", "adv_overflow_chunk.bin", bytes(adv1) + b"\x00" * 96)

    # 4. Adversarial descending / unaligned region directory
    adv2 = build_tbm1_header(
        total_len=512 + 64 + 64,
        regions=[(1, 544, 32), (2, 513, 32)],
        images=[{"slot": 0, "data_off": 1024, "stored": 4096, "installed": 4096, "chunk_sz": 4096, "num_chunks": 1}],
    )
    write_seed("tbm1", "adv_bad_region_order.bin", bytes(adv2) + b"\x11" * 128)

    # 5. Adversarial unknown critical flag & reader downgrade
    adv3 = build_tbm1_header(
        total_len=512 + 32 + 64,
        flags_crit=0x0004,
        min_rmaj=9,
        regions=[(1, 512, 32)],
        images=[{"slot": 0, "data_off": 1024, "stored": 4096, "installed": 4096, "chunk_sz": 4096, "num_chunks": 1}],
    )
    write_seed("tbm1", "adv_unknown_crit_flag.bin", bytes(adv3) + b"\x22" * 96)

    # 6. Truncated
    write_seed("tbm1", "adv_truncated.bin", bytes(hdr[:64]))


def build_tcc1(cmd: int, counter_min: int, issued_at: int, params: bytes, dev_id: bytes = DEVICE_ID, sign: bool = True) -> bytes:
    aligned_plen = (len(params) + 15) & ~15
    total_len = 64 + aligned_plen + 64
    hdr = bytearray(64)
    struct.pack_into(
        "<IBBHIIII32s",
        hdr,
        0,
        0x31434354,
        1,
        cmd,
        0,
        counter_min,
        issued_at,
        len(params),
        total_len,
        dev_id,
    )
    struct.pack_into("<II", hdr, 56, crc32(bytes(hdr[:56])), 0)
    padded_params = params + b"\x00" * (aligned_plen - len(params))
    body = bytes(hdr) + padded_params
    sig = _ed_sign(CLOUD_SEED, CLOUD_PK, body) if sign else b"\x00" * 64
    return body + sig


def build_kdm(seq: int, pubkey: bytes = CLOUD_PK, sign: bool = True) -> bytes:
    body = struct.pack("<I32s", seq, pubkey)
    sig = _ed_sign(ROOT_SEED, ROOT_PK, body) if sign else b"\xAA" * 64
    return body + sig + b"\x00" * 28


def gen_tcc1() -> None:
    write_seed("tcc1", "valid_force_update.bin", build_tcc1(1, 2, 1500, b""))
    write_seed("tcc1", "valid_rotate_key.bin", build_tcc1(4, 2, 1600, build_kdm(10)))
    write_seed("tcc1", "adv_counter_exhaust.bin", build_tcc1(2, 100, 1700, b""))
    bad_len = bytearray(build_tcc1(1, 2, 1800, b"ABCD"))
    struct.pack_into("<II", bad_len, 16, 0xFFFFFFF0, 132)
    struct.pack_into("<I", bad_len, 56, crc32(bytes(bad_len[:56])))
    write_seed("tcc1", "adv_unaligned_total.bin", bytes(bad_len))
    write_seed("tcc1", "adv_replay_stale.bin", build_tcc1(3, 0, 0, b"", sign=False))
    write_seed("tcc1", "adv_erased_ff.bin", b"\xFF" * 128)


def rstore_slot(seq: int, erase_cnt: int, record: bytes, magic: int = 0x4B444D51, corrupt_crc: bool = False) -> bytes:
    buf = bytearray(16) + bytearray(record)
    struct.pack_into("<IIII", buf, 0, magic, seq, erase_cnt, 0)
    c = crc32(bytes(buf))
    if corrupt_crc:
        c ^= 0x00000001
    struct.pack_into("<I", buf, 12, c)
    return bytes(buf)


def gen_kdm() -> None:
    k5 = build_kdm(5)
    s = rstore_slot(5, 1, k5)
    write_seed("kdm", "valid_quorum_3slots.bin", s * 3)

    s_bad = rstore_slot(6, 1, k5, corrupt_crc=True)
    s_old = rstore_slot(4, 1, build_kdm(4))
    write_seed("kdm", "adv_split_quorum_heal.bin", s_bad + s_old + s)
    write_seed("kdm", "adv_kdm_downgrade.bin", build_kdm(3))
    write_seed("kdm", "adv_zero_pubkey.bin", build_kdm(7, pubkey=b"\x00" * 32))

    # Stage 1.5 Auth payload COBS-wrapped
    nonce = bytes(range(32))
    auth_msg = nonce + b"\x01" + b"\x00" * 31 + struct.pack("<II", 2, 1)
    auth_sig = _ed_sign(ROOT_SEED, ROOT_PK, auth_msg)
    auth_payload = struct.pack("<II32s64s", 2, 1, nonce, auth_sig)
    write_seed("kdm", "adv_cobs_stage15_auth.bin", cobs_encode(auth_payload))


def build_tmr_payload(seq_floor: int = 0, chain_cnt: int = 1, ver: int = 9) -> bytes:
    buf = bytearray(112)
    struct.pack_into("<HH", buf, 0, ver, 112)
    struct.pack_into("<I", buf, 44, seq_floor)  # kdm_seq_floor
    struct.pack_into("<I", buf, 68, chain_cnt)  # chain_entry_count
    clean = bytearray(buf)
    clean[52:68] = b"\x00" * 16
    mac = hashlib.sha256(b"K4TM" + JOURNAL_KEY + bytes(clean) + struct.pack("<I", 0)).digest()[:16]
    buf[52:68] = mac
    return bytes(buf)


def build_wal_sector_hdr(seq_id: int, erase_cnt: int, tmr: bytes, magic: int = 0x57414C03) -> bytes:
    buf = bytearray(128)
    struct.pack_into("<III", buf, 0, magic, seq_id, erase_cnt)
    buf[12:124] = tmr
    struct.pack_into("<I", buf, 124, crc32(bytes(buf[:124])))
    return bytes(buf)


def build_wal_entry(intent: int, seq_id: int, entry_off: int, nonce: int = 0) -> bytes:
    buf = bytearray(64)
    struct.pack_into("<IIQ", buf, 0, 0xB007BEEF, intent, nonce)
    if intent in (3, 4, 13):
        clean = bytearray(buf[:60])
        clean[36:52] = b"\x00" * 16
        mac = hashlib.sha256(
            b"K4EN" + JOURNAL_KEY + struct.pack("<II", seq_id, entry_off) + bytes(clean)
        ).digest()[:16]
        buf[36:52] = mac
    struct.pack_into("<I", buf, 60, crc32(bytes(buf[:60])))
    return bytes(buf)


def gen_wal_journal() -> None:
    tmr = build_tmr_payload(seq_floor=1, chain_cnt=3)
    sec0 = bytearray(b"\xFF" * 256)
    sec0[0:128] = build_wal_sector_hdr(1, 1, tmr)
    sec0[128:192] = build_wal_entry(4, 1, 128, nonce=0x1122334455667788)
    sec1 = bytearray(b"\xFF" * 256)
    sec1[0:128] = build_wal_sector_hdr(2, 1, tmr)
    sec2 = bytearray(b"\xFF" * 256)
    sec2[0:128] = build_wal_sector_hdr(3, 1, tmr)
    sec3 = bytearray(b"\xFF" * 256)
    write_seed("wal_journal", "valid_3sector_tmr.bin", bytes(sec0 + sec1 + sec2 + sec3))

    # Torn entry after valid header
    torn = bytearray(sec2)
    torn[128:160] = b"\xEF\xBE\x07\xB0" + b"\x55" * 28
    write_seed("wal_journal", "adv_torn_entry.bin", bytes(sec0 + sec1 + torn + sec3))

    # Future TMR version trap
    fut_tmr = build_tmr_payload(ver=99)
    fut_sec = bytearray(b"\xFF" * 256)
    fut_sec[0:128] = build_wal_sector_hdr(10, 1, fut_tmr)
    write_seed("wal_journal", "adv_tmr_future_ver.bin", bytes(fut_sec) * 4)

    # Bad K4 MAC
    bad_tmr = bytearray(tmr)
    bad_tmr[52] ^= 0xFF
    bad_sec = bytearray(b"\xFF" * 256)
    bad_sec[0:128] = build_wal_sector_hdr(1, 1, bytes(bad_tmr))
    write_seed("wal_journal", "adv_bad_mac.bin", bytes(bad_sec) * 4)

    write_seed("wal_journal", "adv_all_erased.bin", b"\xFF" * 512)


def build_mailbox(req: int, seq: int, tbm1_addr: int, nonce: int, bad_crc: bool = False) -> bytes:
    buf = bytearray(32)
    struct.pack_into("<IHHIQ", buf, 0, 0x58424D54, 2, req, seq, tbm1_addr)
    struct.pack_into("<Q", buf, 16, nonce)
    c = crc32(bytes(buf[:24]))
    if bad_crc:
        c ^= 0x1234
    struct.pack_into("<II", buf, 24, c, 0)
    return bytes(buf)


def gen_cobs_mailbox() -> None:
    frame = cobs_encode(b"\x06\x00\xAA\xBB\xCC\xDD")
    write_seed("cobs_mailbox", "valid_cobs_frame.bin", frame[1:])

    m0 = build_mailbox(0x0002, 0x7FFFFFFF, 0, 0x5566778811223344)
    m1 = build_mailbox(0x0003, 0x80000001, 0x38000, 0x5566778811223344)
    write_seed("cobs_mailbox", "valid_mbx_ab_wrap.bin", m0 + m1)

    overflow = b"\x41" * 180 + b"\x00" + frame
    write_seed("cobs_mailbox", "adv_cobs_overflow_drain.bin", overflow)
    write_seed("cobs_mailbox", "adv_cobs_truncated_code.bin", b"\x50ABCD")
    write_seed("cobs_mailbox", "adv_mbx_zero_nonce_confirm.bin", build_mailbox(0x0002, 2, 0, 0) * 2)


def xmodem_packet(blk: int, payload128: bytes) -> bytes:
    assert len(payload128) == 128
    crc = crc16_ccitt(payload128)
    return bytes([0x01, blk & 0xFF, 0xFF - (blk & 0xFF)]) + payload128 + struct.pack(">H", crc)


def gen_xmodem() -> None:
    # 1. Valid 5-block Head-TBM1 stream (640B) + EOT
    tbm1 = build_tbm1_header(
        total_len=640,
        regions=[(1, 512, 32)],
        images=[{"slot": 0, "data_off": 640, "stored": 128, "installed": 128, "chunk_sz": 4096, "num_chunks": 1}],
    )
    stream1 = bytearray()
    img_blob = bytes(tbm1) + b"\xAA" * 128 + b"\xBB" * 128
    for blk in range(1, 6):
        chunk = img_blob[(blk - 1) * 128 : blk * 128]
        stream1.extend(xmodem_packet(blk, chunk))
    stream1.append(0x04)  # EOT
    write_seed("xmodem", "valid_head_tbm1_stream.bin", bytes(stream1))

    # 2. Valid Trailer-TBM1 stream with split 16B TBMT locator across block 5 & 6 boundary
    raw_app = bytearray(632)
    struct.pack_into("<III8s", raw_app, 0, 0x544F4F42, 64, 0x100, b"\x00" * 8)
    loc_hdr = struct.pack("<III", 0x544D4254, 512, 576)
    loc = loc_hdr + struct.pack("<I", crc32(loc_hdr))
    # Put locator at offset 512+120 = 632 (spans block 5 bytes 120..127 and block 6 bytes 0..7)
    raw_app = bytes(raw_app[:632]) + loc + b"\x1A" * (768 - 648)
    stream2 = bytearray()
    for blk in range(1, 7):
        stream2.extend(xmodem_packet(blk, raw_app[(blk - 1) * 128 : blk * 128]))
    stream2.append(0x04)
    write_seed("xmodem", "valid_trailer_split_stream.bin", bytes(stream2))

    # 3. Adversarial complement mismatch + CAN
    bad_comp = bytes([0x01, 0x01, 0x01]) + b"\x00" * 130 + bytes([0x18])
    write_seed("xmodem", "adv_bad_complement.bin", bad_comp)

    # 4. STX + 1-byte checksum + CAN
    write_seed("xmodem", "adv_stx_checksum.bin", bytes([0x02, 0x01, 0xFE]) + b"\x55" * 129 + bytes([0x18]))

    # 5. Bad CRC16 + duplicate block + EOT
    pkt1 = bytearray(xmodem_packet(1, b"\x11" * 128))
    pkt1[-1] ^= 0xFF
    write_seed("xmodem", "adv_bad_crc16.bin", bytes(pkt1) + xmodem_packet(1, b"\x11" * 128) + bytes([0x04]))

    # 6. Oversized head manifest + EOT
    big_tbm1 = build_tbm1_header(
        total_len=0x7FFFFFFF,
        regions=[(1, 512, 32)],
        images=[{"slot": 0, "data_off": 0x70000000, "stored": 0x10000000, "installed": 4096, "chunk_sz": 4096, "num_chunks": 1}],
    )
    s_big = bytearray()
    padded = bytes(big_tbm1) + b"\x00" * 128
    for blk in range(1, 6):
        s_big.extend(xmodem_packet(blk, padded[(blk - 1) * 128 : blk * 128]))
    s_big.append(0x04)
    write_seed("xmodem", "adv_oversized_manifest.bin", bytes(s_big))


def gen_decomp_delta() -> None:
    base_pat = b"TOOB_BASE_IMAGE_V1_REFERENCE_PAYLOAD_0123456789ABCDEF0123456789\x00" * 64
    base_4k = base_pat[:4096]
    fp = hashlib.sha256(base_4k).digest()[:8]

    # 1. Valid TDS1 patch: COPY_BASE(2048) + BZERO(2048) + EOF
    instrs = bytearray()
    for op, length, off in [(0xC0C0C0C0, 2048, 0), (0x5A5A5A5A, 2048, 0), (0x0F0F0F0F, 0, 0)]:
        raw_i = struct.pack("<III", op, length, off)
        instrs.extend(raw_i + struct.pack("<I", crc32(raw_i)))
    lit_off = 32 + len(instrs)
    hdr_wo_crc = struct.pack("<II8sIII", 0x31534454, 4096, fp, 4096, lit_off, 3)
    hdr = hdr_wo_crc + struct.pack("<I", crc32(hdr_wo_crc))
    write_seed("decomp_delta", "valid_tds1_bzero_copy.bin", hdr + bytes(instrs))

    # 2. Adversarial integer overflow instr_count
    ov_wo = struct.pack("<II8sIII", 0x31534454, 4096, fp, 4096, 0x40, 0x10000001)
    write_seed("decomp_delta", "adv_tds1_overflow_cnt.bin", ov_wo + struct.pack("<I", crc32(ov_wo)) + b"\x00" * 16)

    # 3. Bad EOF instr (non-zero length)
    bad_eof_i = struct.pack("<III", 0x0F0F0F0F, 128, 0)
    bad_eof = bad_eof_i + struct.pack("<I", crc32(bad_eof_i))
    be_wo = struct.pack("<II8sIII", 0x31534454, 4096, fp, 4096, 48, 1)
    write_seed("decomp_delta", "adv_tds1_bad_eof.bin", be_wo + struct.pack("<I", crc32(be_wo)) + bad_eof)

    # 4. Heatshrink compressed stream (valid literal + backref bit pattern)
    # 0x80.. bytes trigger heatshrink backref loops to test zip-bomb target size cap
    write_seed("decomp_delta", "adv_hs_zipbomb.bin", b"\x00\x01\x00\x00" + b"\x80\x00\xFF\x0F" * 32)
    write_seed("decomp_delta", "adv_hs_corrupt.bin", b"\x01\x00\x00\x00" + bytes(range(64)))


def gen_multiimage() -> None:
    payload = b"\xDE\xAD\xBE\xEF" * 64
    img_hdr = struct.pack("<III8s", 0x544F4F42, 20 + len(payload) + 72, 0x100, b"\x00" * 8)
    signed_body = img_hdr + payload
    digest = hashlib.sha256(signed_body).digest()
    tsig = struct.pack("<IBBH64s", 0x54534947, 0, 1, 0, _ed_sign(ROOT_SEED, ROOT_PK, digest))
    full_img = signed_body + tsig

    comp = struct.pack(
        "<IIII32sIIII",
        0,
        0,
        0x00028000,
        len(full_img),
        hashlib.sha256(full_img).digest(),
        0,
        0,
        0,
        0,
    )
    write_seed("multiimage", "valid_comp_and_tsig.bin", comp + full_img)

    # Escape to Stage 0 / uint32 wraparound
    esc1 = struct.pack("<IIII32sIIII", 0, 0, 0x00000000, 4096, b"\x00" * 32, 0, 0, 0, 0)
    esc2 = struct.pack("<IIII32sIIII", 1, 0, 0xFFFFFFF0, 32, b"\x00" * 32, 0, 0, 0, 0)
    write_seed("multiimage", "adv_stage0_whitelist_escape.bin", esc1 + esc2)

    # Duplicate / out-of-range component ID
    d1 = struct.pack("<IIII32sIIII", 32, 0, 0x00028000, 256, b"\x00" * 32, 0, 0, 0, 0)
    d2 = struct.pack("<IIII32sIIII", 0, 0, 0x00028000, 256, b"\x00" * 32, 0, 0, 0, 0)
    write_seed("multiimage", "adv_dup_comp_id.bin", d1 + d2 + d2)

    # Bad TSIG reserved / flags
    bad_tsig = struct.pack("<IBBH64s", 0x54534947, 0, 2, 1, b"\x55" * 64)
    write_seed("multiimage", "adv_bad_tsig_reserved.bin", signed_body + bad_tsig)
    write_seed("multiimage", "adv_truncated_image.bin", img_hdr)


def main() -> None:
    gen_tbm1()
    gen_tcc1()
    gen_kdm()
    gen_wal_journal()
    gen_cobs_mailbox()
    gen_xmodem()
    gen_decomp_delta()
    gen_multiimage()
    total = 0
    for d in sorted(os.listdir(CORPUS_ROOT)):
        p = os.path.join(CORPUS_ROOT, d)
        if os.path.isdir(p):
            cnt = len(os.listdir(p))
            total += cnt
            print(f"corpus/{d}: {cnt} seeds")
    print(f"Total seeds generated: {total}")


if __name__ == "__main__":
    main()
