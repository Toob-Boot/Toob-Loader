#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

use libtoob::{
    confirm_boot, define_platform, get_boot_diag, get_boot_diag_wire, get_device_id, get_handoff,
    sys, OtaSession, PlatformHooks, Result, ToobError,
};

const APP_VERSION: &str = match option_env!("TOOB_RUST_APP_VER") {
    Some(v) => v,
    None => "1.0.0",
};

const CRASH_ON_BOOT: bool = match option_env!("TOOB_RUST_CRASH_ON_BOOT") {
    Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
    None => false,
};

// Nordic nRF52840 MMIO & Flash Geometry
const FLASH_XIP_BASE: u32 = 0x0000_0000;
const FLASH_TOTAL_SIZE: u32 = 0x0010_0000;
const FLASH_WRITE_ALIGN: u32 = 4;
const FLASH_PAGE_SIZE: u32 = 4096;
const STAGE0_PROBE_ADDR: u32 = 0x0000_1000;

const REG_POWER_GPREGRET: usize = 0x4000_051C;
const REG_BPROT_CONFIG0: usize = 0x4000_0600;

const REG_UART0_TASKS_STARTRX: usize = 0x4000_2000;
const REG_UART0_TASKS_STOPRX: usize = 0x4000_2004;
const REG_UART0_TASKS_STARTTX: usize = 0x4000_2008;
const REG_UART0_TASKS_STOPTX: usize = 0x4000_200C;
const REG_UART0_EVENTS_RXDRDY: usize = 0x4000_2108;
const REG_UART0_EVENTS_TXDRDY: usize = 0x4000_211C;
const REG_UART0_ENABLE: usize = 0x4000_2500;
const REG_UART0_RXD: usize = 0x4000_2518;
const REG_UART0_TXD: usize = 0x4000_251C;
const REG_UART0_BAUDRATE: usize = 0x4000_2524;
const UART0_BAUD_115200: u32 = 0x01D7_E000;
const UART0_ENABLE_ON: u32 = 4;
const UART_TX_SPIN_LIMIT: u32 = 200_000;

const REG_WDT_RUNSTATUS: usize = 0x4001_0400;
const REG_WDT_RR0: usize = 0x4001_0600;
const WDT_RELOAD_MAGIC: u32 = 0x6E52_4635;

const REG_NVMC_READY: usize = 0x4001_E400;
const REG_NVMC_CONFIG: usize = 0x4001_E504;
const REG_NVMC_ERASEPAGE: usize = 0x4001_E508;
const REG_NVMC_ICACHECNF: usize = 0x4001_E540;
const NVMC_MODE_REN: u32 = 0;
const NVMC_MODE_WEN: u32 = 1;
const NVMC_MODE_EEN: u32 = 2;
const NVMC_SPIN_LIMIT: u32 = 2_000_000;

const CONFIRM_STORAGE_BASE: usize = 0x2003_FFC0;

const SCB_AIRCR_ADDR: usize = 0xE000_ED0C;
const SCB_AIRCR_SYSRESETREQ: u32 = 0x05FA_0004;

const OTA_CHUNK_MAX: usize = 512;

global_asm!(
    ".section .isr_vector, \"a\", %progbits",
    ".align 2",
    ".global _isr_vector_table",
    "_isr_vector_table:",
    "    .word _stack_top",
    "    .word _app_start",
    "    .word _app_fault_trap",
    "    .word _app_fault_trap",
    "    .word _app_fault_trap",
    "    .word _app_fault_trap",
    "    .word _app_fault_trap",
    "    .word 0",
    "    .word 0",
    "    .word 0",
    "    .word 0",
    "    .word _app_fault_trap",
    "    .word _app_fault_trap",
    "    .word 0",
    "    .word _app_fault_trap",
    "    .word _app_fault_trap",
    "",
    ".section .app_entry, \"ax\", %progbits",
    ".global _app_start",
    ".thumb_func",
    "_app_start:",
    "    cpsid i",
    "    ldr r0, =_stack_top",
    "    mov sp, r0",
    "    ldr r0, =0xE000ED88",
    "    ldr r1, [r0]",
    "    orr r1, r1, #0x00F00000",
    "    str r1, [r0]",
    "    dsb sy",
    "    isb sy",
    "    bl _app_rust_init",
    ".global _app_fault_trap",
    ".thumb_func",
    "_app_fault_trap:",
    "    wfi",
    "    b _app_fault_trap",
);

extern "C" {
    static _sidata: u32;
    static mut _data_start: u32;
    static mut _data_end: u32;
    static mut _bss_start: u32;
    static mut _bss_end: u32;
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_puts("\n[RUST] PANIC\n");
    loop {
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

#[inline(always)]
fn mmio_read32(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn mmio_write32(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

#[inline(always)]
fn wdt_kick() {
    if (mmio_read32(REG_WDT_RUNSTATUS) & 1) != 0 {
        mmio_write32(REG_WDT_RR0, WDT_RELOAD_MAGIC);
    }
}

fn uart_init() {
    mmio_write32(REG_UART0_TASKS_STOPRX, 1);
    mmio_write32(REG_UART0_TASKS_STOPTX, 1);
    mmio_write32(REG_UART0_ENABLE, 0);
    mmio_write32(REG_UART0_BAUDRATE, UART0_BAUD_115200);
    mmio_write32(REG_UART0_EVENTS_RXDRDY, 0);
    mmio_write32(REG_UART0_EVENTS_TXDRDY, 0);
    mmio_write32(REG_UART0_ENABLE, UART0_ENABLE_ON);
    mmio_write32(REG_UART0_TASKS_STARTRX, 1);
    mmio_write32(REG_UART0_TASKS_STARTTX, 1);
}

fn uart_putc(b: u8) {
    mmio_write32(REG_UART0_EVENTS_TXDRDY, 0);
    mmio_write32(REG_UART0_TASKS_STARTTX, 1);
    mmio_write32(REG_UART0_TXD, b as u32);
    for _ in 0..UART_TX_SPIN_LIMIT {
        if mmio_read32(REG_UART0_EVENTS_TXDRDY) != 0 {
            break;
        }
    }
}

fn uart_puts(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            uart_putc(b'\r');
        }
        uart_putc(b);
    }
}

fn uart_put_u32(mut val: u32) {
    if val == 0 {
        uart_putc(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut idx = 0usize;
    while val > 0 {
        buf[idx] = b'0' + (val % 10) as u8;
        val /= 10;
        idx += 1;
    }
    while idx > 0 {
        idx -= 1;
        uart_putc(buf[idx]);
    }
}

fn uart_put_hex32(val: u32) {
    for i in 0..8 {
        let nib = ((val >> ((7 - i) * 4)) & 0xF) as u8;
        uart_putc(if nib < 10 { b'0' + nib } else { b'A' + (nib - 10) });
    }
}

fn uart_getc_wdt_safe() -> u8 {
    let mut spin = 0u32;
    loop {
        if mmio_read32(REG_UART0_EVENTS_RXDRDY) != 0 {
            mmio_write32(REG_UART0_EVENTS_RXDRDY, 0);
            return (mmio_read32(REG_UART0_RXD) & 0xFF) as u8;
        }
        spin = spin.wrapping_add(1);
        if (spin & 0xFFFF) == 0 {
            wdt_kick();
        }
    }
}

fn uart_read_line(buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    while pos < buf.len() {
        let b = uart_getc_wdt_safe();
        if b == b'\r' {
            continue;
        }
        if b == b'\n' {
            break;
        }
        buf[pos] = b;
        pos += 1;
    }
    pos
}

fn parse_u32_dec(bytes: &[u8]) -> (u32, usize) {
    let mut val = 0u32;
    let mut consumed = 0usize;
    for &b in bytes {
        if !b.is_ascii_digit() {
            break;
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
        consumed += 1;
    }
    (val, consumed)
}

fn parse_hex_sha256(hex: &[u8]) -> Option<[u8; 32]> {
    if hex.len() < 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn nvmc_wait_ready() -> bool {
    for _ in 0..NVMC_SPIN_LIMIT {
        if (mmio_read32(REG_NVMC_READY) & 1) != 0 {
            return true;
        }
    }
    false
}

fn nvmc_sync_icache() {
    let cnf = mmio_read32(REG_NVMC_ICACHECNF);
    if (cnf & 1) != 0 {
        mmio_write32(REG_NVMC_ICACHECNF, cnf & !1);
        mmio_write32(REG_NVMC_ICACHECNF, cnf);
    }
    unsafe {
        asm!("dsb sy", "isb sy", options(nostack, preserves_flags));
    }
}

fn system_reboot_intentional() -> ! {
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
    mmio_write32(SCB_AIRCR_ADDR, SCB_AIRCR_SYSRESETREQ);
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
    loop {
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }
}

// ============================================================================
// Software FIPS 180-4 SHA-256 (zero-unsafe, alignment-independent)
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let b = &block[i * 4..i * 4 + 4];
        w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// ============================================================================
// libtoob PlatformHooks Implementation over Real nRF52840 Peripherals
// ============================================================================

struct Nrf52840Platform;

impl PlatformHooks for Nrf52840Platform {
    fn flash_read(addr: u32, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len() as u32;
        if addr > FLASH_TOTAL_SIZE || len > (FLASH_TOTAL_SIZE - addr) {
            return Err(ToobError::FlashFailure);
        }
        wdt_kick();
        let src = (FLASH_XIP_BASE + addr) as *const u8;
        for (i, dst) in buf.iter_mut().enumerate() {
            *dst = unsafe { read_volatile(src.add(i)) };
        }
        Ok(())
    }

    fn flash_write(addr: u32, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Err(ToobError::InvalidArg);
        }
        let len = buf.len() as u32;
        if (addr % FLASH_WRITE_ALIGN) != 0 || (len % FLASH_WRITE_ALIGN) != 0 {
            return Err(ToobError::FlashFailure);
        }
        if addr > FLASH_TOTAL_SIZE || len > (FLASH_TOTAL_SIZE - addr) {
            return Err(ToobError::FlashFailure);
        }
        if !nvmc_wait_ready() {
            return Err(ToobError::FlashFailure);
        }

        mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_WEN);
        if !nvmc_wait_ready() {
            mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_REN);
            return Err(ToobError::FlashFailure);
        }

        let mut off = 0usize;
        while off < buf.len() {
            wdt_kick();
            let word = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            mmio_write32((FLASH_XIP_BASE + addr + off as u32) as usize, word);
            if !nvmc_wait_ready() {
                mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_REN);
                return Err(ToobError::FlashFailure);
            }
            off += 4;
        }

        mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_REN);
        let _ = nvmc_wait_ready();
        nvmc_sync_icache();
        Ok(())
    }

    fn flash_erase(addr: u32, len: u32) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        if (addr % FLASH_PAGE_SIZE) != 0 {
            return Err(ToobError::FlashFailure);
        }
        if addr > FLASH_TOTAL_SIZE || len > (FLASH_TOTAL_SIZE - addr) {
            return Err(ToobError::FlashFailure);
        }
        if !nvmc_wait_ready() {
            return Err(ToobError::FlashFailure);
        }

        mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_EEN);
        if !nvmc_wait_ready() {
            mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_REN);
            return Err(ToobError::FlashFailure);
        }

        let pages = (len + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE;
        for i in 0..pages {
            wdt_kick();
            mmio_write32(REG_NVMC_ERASEPAGE, addr + i * FLASH_PAGE_SIZE);
            if !nvmc_wait_ready() {
                mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_REN);
                return Err(ToobError::FlashFailure);
            }
        }

        mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_REN);
        let _ = nvmc_wait_ready();
        nvmc_sync_icache();
        Ok(())
    }

    fn sha256_init(ctx: &mut [u8; 128]) -> Result<()> {
        ctx.fill(0);
        let init: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        for (i, word) in init.into_iter().enumerate() {
            ctx[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(())
    }

    fn sha256_update(ctx: &mut [u8; 128], data: &[u8]) -> Result<()> {
        wdt_kick();
        let mut state = [0u32; 8];
        for i in 0..8 {
            let b = &ctx[i * 4..i * 4 + 4];
            state[i] = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        let mut total_bytes = u64::from_le_bytes([
            ctx[32], ctx[33], ctx[34], ctx[35], ctx[36], ctx[37], ctx[38], ctx[39],
        ]);
        let mut block_len =
            u32::from_le_bytes([ctx[104], ctx[105], ctx[106], ctx[107]]) as usize;

        total_bytes = total_bytes.wrapping_add(data.len() as u64);
        let mut pos = 0usize;
        while pos < data.len() {
            let space = 64 - block_len;
            let take = (data.len() - pos).min(space);
            ctx[40 + block_len..40 + block_len + take].copy_from_slice(&data[pos..pos + take]);
            block_len += take;
            pos += take;

            if block_len == 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&ctx[40..104]);
                sha256_compress(&mut state, &block);
                block_len = 0;
            }
        }

        for (i, word) in state.into_iter().enumerate() {
            ctx[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        ctx[32..40].copy_from_slice(&total_bytes.to_le_bytes());
        ctx[104..108].copy_from_slice(&(block_len as u32).to_le_bytes());
        Ok(())
    }

    fn sha256_finalize(ctx: &mut [u8; 128], out_hash: &mut [u8; 32]) -> Result<()> {
        let mut state = [0u32; 8];
        for i in 0..8 {
            let b = &ctx[i * 4..i * 4 + 4];
            state[i] = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        let total_bytes = u64::from_le_bytes([
            ctx[32], ctx[33], ctx[34], ctx[35], ctx[36], ctx[37], ctx[38], ctx[39],
        ]);
        let mut block_len =
            u32::from_le_bytes([ctx[104], ctx[105], ctx[106], ctx[107]]) as usize;
        let mut block = [0u8; 64];
        block.copy_from_slice(&ctx[40..104]);

        block[block_len] = 0x80;
        block_len += 1;

        if block_len > 56 {
            block[block_len..64].fill(0);
            sha256_compress(&mut state, &block);
            block.fill(0);
        } else {
            block[block_len..56].fill(0);
        }

        let bit_len = total_bytes.wrapping_mul(8);
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut state, &block);

        for (i, word) in state.into_iter().enumerate() {
            out_hash[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        ctx.fill(0);
        Ok(())
    }

    fn lock() {
        compiler_fence(Ordering::SeqCst);
    }

    fn unlock() {
        compiler_fence(Ordering::SeqCst);
    }

    fn confirm_rtc_write(nonce: u64) -> Result<()> {
        let lo = (nonce & 0xFFFF_FFFF) as u32;
        let hi = (nonce >> 32) as u32;
        mmio_write32(CONFIRM_STORAGE_BASE, lo);
        mmio_write32(CONFIRM_STORAGE_BASE + 4, hi);
        mmio_write32(REG_POWER_GPREGRET, (lo & 0x7F) | 0x80);
        unsafe {
            asm!("dmb sy", options(nostack, preserves_flags));
        }
        let rb_lo = mmio_read32(CONFIRM_STORAGE_BASE);
        let rb_hi = mmio_read32(CONFIRM_STORAGE_BASE + 4);
        if rb_lo == lo && rb_hi == hi {
            Ok(())
        } else {
            Err(ToobError::VerificationFailure)
        }
    }
}

define_platform!(Nrf52840Platform);

// ============================================================================
// Interactive Commands (OTA / OTAV / CONFIRM / DIAG / BPROT_ATTACK / REBOOT)
// ============================================================================

fn handle_bprot_attack() {
    wdt_kick();
    let cfg0 = mmio_read32(REG_BPROT_CONFIG0);
    let pre_word = mmio_read32(STAGE0_PROBE_ADDR as usize);

    mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_EEN);
    let _ = nvmc_wait_ready();
    mmio_write32(REG_NVMC_ERASEPAGE, STAGE0_PROBE_ADDR);
    let _ = nvmc_wait_ready();

    mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_WEN);
    let _ = nvmc_wait_ready();
    mmio_write32(STAGE0_PROBE_ADDR as usize, 0);
    let _ = nvmc_wait_ready();
    mmio_write32(REG_NVMC_CONFIG, NVMC_MODE_REN);
    let _ = nvmc_wait_ready();
    nvmc_sync_icache();

    let post_word = mmio_read32(STAGE0_PROBE_ADDR as usize);
    let protected = post_word == pre_word && post_word != 0;

    uart_puts("[RUST] BPROT cfg0=0x");
    uart_put_hex32(cfg0);
    uart_puts(" pre=0x");
    uart_put_hex32(pre_word);
    uart_puts(" post=0x");
    uart_put_hex32(post_word);
    uart_puts(if protected {
        " status=PROTECTED\n"
    } else {
        " status=MODIFIED\n"
    });
}

fn handle_ota_stream(total_len: u32, expected_sha256: Option<[u8; 32]>) {
    let idle = match OtaSession::new() {
        Ok(s) => s,
        Err(_) => {
            uart_puts("[RUST] OTA_ERR init\n");
            return;
        }
    };

    let mut rx_session = match expected_sha256.as_ref() {
        Some(hash) => match idle.begin_verified(total_len, hash) {
            Ok(s) => s,
            Err(_) => {
                uart_puts("[RUST] OTA_ERR begin_verified\n");
                return;
            }
        },
        None => match idle.begin(total_len) {
            Ok(s) => s,
            Err(_) => {
                uart_puts("[RUST] OTA_ERR begin\n");
                return;
            }
        },
    };

    uart_puts("[RUST] OTA_READY\n");

    let mut chunk_buf = [0u8; OTA_CHUNK_MAX];
    let mut rx_total = 0u32;

    while rx_total < total_len {
        let lo = uart_getc_wdt_safe() as u16;
        let hi = uart_getc_wdt_safe() as u16;
        let clen = (lo | (hi << 8)) as usize;
        if clen == 0 || clen > OTA_CHUNK_MAX || (clen as u32) > (total_len - rx_total) {
            let _ = rx_session.abort();
            uart_puts("[RUST] OTA_ERR len\n");
            return;
        }
        for b in &mut chunk_buf[..clen] {
            *b = uart_getc_wdt_safe();
        }
        wdt_kick();
        if rx_session.process_chunk(&chunk_buf[..clen]).is_err() {
            let _ = rx_session.abort();
            uart_puts("[RUST] OTA_ERR chunk\n");
            return;
        }
        rx_total += clen as u32;
        uart_putc(b'K');
    }

    wdt_kick();
    match rx_session.finalize() {
        Ok(_done) => {
            if expected_sha256.is_some() {
                uart_puts("\n[RUST] OTA_FINALIZED mode=SHA256 status=OK\n");
            } else {
                uart_puts("\n[RUST] OTA_FINALIZED mode=UNVERIFIED status=OK\n");
            }
            system_reboot_intentional();
        }
        Err(e) => {
            uart_puts("\n[RUST] OTA_ERR finalize=0x");
            uart_put_hex32(e.to_status().0);
            uart_puts("\n");
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn _app_rust_init() -> ! {
    // Initialize .data from Flash LMA -> SRAM VMA
    let mut src = &raw const _sidata;
    let mut dst = &raw mut _data_start;
    let data_end = &raw mut _data_end;
    while (dst as usize) < (data_end as usize) {
        write_volatile(dst, read_volatile(src));
        src = src.add(1);
        dst = dst.add(1);
    }

    // Zero .bss in SRAM
    let mut bss = &raw mut _bss_start;
    let bss_end = &raw mut _bss_end;
    while (bss as usize) < (bss_end as usize) {
        write_volatile(bss, 0);
        bss = bss.add(1);
    }

    uart_init();
    wdt_kick();

    let handoff = get_handoff();
    let diag = get_boot_diag();
    let dev_id_ok = get_device_id().is_ok();

    let (slot, tentative, handoff_ok) = match handoff {
        Ok(h) => (
            h.active_slot as u32,
            u32::from(h.magic == sys::TOOB_STATE_TENTATIVE),
            true,
        ),
        Err(_) => (99, 0, false),
    };
    let diag_svn = diag.map(|d| d.installed_app_svn).unwrap_or(999);

    if CRASH_ON_BOOT {
        uart_puts("RUST_GUEST v");
        uart_puts(APP_VERSION);
        uart_puts(" slot=");
        uart_put_u32(slot);
        uart_puts(" tent=");
        uart_put_u32(tentative);
        uart_puts(" CRASHING_WITHOUT_CONFIRM\n");
        loop {
            asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }

    uart_puts("RUST_GUEST v");
    uart_puts(APP_VERSION);
    uart_puts(" slot=");
    uart_put_u32(slot);
    uart_puts(" tent=");
    uart_put_u32(tentative);
    uart_puts(" handoff=");
    uart_puts(if handoff_ok && dev_id_ok { "OK" } else { "ERR" });
    uart_puts(" diag_svn=");
    uart_put_u32(diag_svn);
    uart_puts("\n");

    let mut line = [0u8; 128];
    loop {
        let n = uart_read_line(&mut line);
        if n == 0 {
            continue;
        }
        let cmd = &line[..n];
        if cmd == b"CONFIRM" {
            match confirm_boot() {
                Ok(()) => uart_puts("[RUST] CONFIRM status=OK\n"),
                Err(e) => {
                    uart_puts("[RUST] CONFIRM status=ERR code=0x");
                    uart_put_hex32(e.to_status().0);
                    uart_puts("\n");
                }
            }
        } else if cmd == b"DIAG" {
            let mut wire = [0u8; 256];
            match (get_boot_diag(), get_boot_diag_wire(&mut wire)) {
                (Ok(d), Ok(wire_len)) => {
                    uart_puts("[RUST] DIAG wire_len=");
                    uart_put_u32(wire_len as u32);
                    uart_puts(" svn=");
                    uart_put_u32(d.current_svn);
                    uart_puts(" outcome=");
                    uart_put_u32(d.last_update_outcome as u32);
                    uart_puts("\n");
                }
                _ => uart_puts("[RUST] DIAG status=ERR\n"),
            }
        } else if cmd == b"BPROT_ATTACK" {
            handle_bprot_attack();
        } else if cmd == b"REBOOT" {
            uart_puts("[RUST] REBOOTING\n");
            system_reboot_intentional();
        } else if cmd.starts_with(b"OTAV ") {
            let rest = &cmd[5..];
            let (total_len, used) = parse_u32_dec(rest);
            if used > 0 && rest.len() > used + 1 && rest[used] == b' ' {
                if let Some(sha) = parse_hex_sha256(&rest[used + 1..]) {
                    handle_ota_stream(total_len, Some(sha));
                } else {
                    uart_puts("[RUST] OTA_ERR sha_parse\n");
                }
            } else {
                uart_puts("[RUST] OTA_ERR args\n");
            }
        } else if cmd.starts_with(b"OTA ") {
            let (total_len, used) = parse_u32_dec(&cmd[4..]);
            if used > 0 {
                handle_ota_stream(total_len, None);
            } else {
                uart_puts("[RUST] OTA_ERR args\n");
            }
        } else if cmd == b"PING" {
            uart_puts("[RUST] PONG ver=");
            uart_puts(APP_VERSION);
            uart_puts("\n");
        }
    }
}
