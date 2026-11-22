use core::mem::offset_of;
use std::sync::Mutex;

use libtoob::{confirm_boot, define_platform, sys, PlatformHooks, Result, ToobError};

const FLASH_SIZE: usize = 0x10_0000;
const SECTOR_SIZE: u32 = 0x4000;

static FLASH: Mutex<[u8; FLASH_SIZE]> = Mutex::new([0xFF; FLASH_SIZE]);

struct MinimalPlatform;

impl PlatformHooks for MinimalPlatform {
    fn flash_read(addr: u32, buf: &mut [u8]) -> Result<()> {
        let start = addr as usize;
        let end = start.checked_add(buf.len()).ok_or(ToobError::FlashFailure)?;
        let flash = FLASH.lock().unwrap();
        if end > flash.len() {
            return Err(ToobError::FlashFailure);
        }
        buf.copy_from_slice(&flash[start..end]);
        Ok(())
    }

    fn flash_write(addr: u32, buf: &[u8]) -> Result<()> {
        if !addr.is_multiple_of(8) || !buf.len().is_multiple_of(8) {
            return Err(ToobError::FlashFailure);
        }
        let start = addr as usize;
        let end = start.checked_add(buf.len()).ok_or(ToobError::FlashFailure)?;
        let mut flash = FLASH.lock().unwrap();
        if end > flash.len() {
            return Err(ToobError::FlashFailure);
        }
        for (dst, &src) in flash[start..end].iter_mut().zip(buf.iter()) {
            *dst &= src;
        }
        Ok(())
    }

    fn flash_erase(addr: u32, len: u32) -> Result<()> {
        if !addr.is_multiple_of(SECTOR_SIZE) || !len.is_multiple_of(SECTOR_SIZE) {
            return Err(ToobError::FlashFailure);
        }
        let start = addr as usize;
        let end = start.checked_add(len as usize).ok_or(ToobError::FlashFailure)?;
        let mut flash = FLASH.lock().unwrap();
        if end > flash.len() {
            return Err(ToobError::FlashFailure);
        }
        flash[start..end].fill(0xFF);
        Ok(())
    }

    fn sha256_init(_ctx: &mut [u8; 128]) -> Result<()> {
        Err(ToobError::NotSupported)
    }

    fn sha256_update(_ctx: &mut [u8; 128], _data: &[u8]) -> Result<()> {
        Err(ToobError::NotSupported)
    }

    fn sha256_finalize(_ctx: &mut [u8; 128], _out_hash: &mut [u8; 32]) -> Result<()> {
        Err(ToobError::NotSupported)
    }
}

define_platform!(MinimalPlatform);

#[test]
fn six_method_implementer_uses_optional_defaults_cleanly() {
    FLASH.lock().unwrap().fill(0xFF);
    unsafe {
        sys::toob_mailbox_session_reset_for_test();

        let mut h = core::mem::zeroed::<sys::toob_handoff_t>();
        h.magic = sys::TOOB_STATE_TENTATIVE;
        h.struct_version = sys::TOOB_HANDOFF_STRUCT_VERSION;
        h.boot_nonce = 0xCAFE_BABE_1234_5678;
        h.booted_partition = sys::TOOB_PARTITION_APP.0;
        h.reset_reason = sys::TOOB_RESET_SOFTWARE.0;
        let crc_len = offset_of!(sys::toob_handoff_t, crc32_trailer);
        h.crc32_trailer = sys::toob_lib_crc32(core::ptr::addr_of!(h).cast::<u8>(), crc_len);
        sys::toob_handoff_state = h;
    }

    // Default confirm_rtc_write returns NotSupported, so C toob_confirm_boot
    // seamlessly commits the confirmation to the persistent Flash Mailbox.
    confirm_boot().expect("confirm_boot must succeed with default optional hooks");

    let flash = FLASH.lock().unwrap();
    let mbx_magic = u32::from_le_bytes(flash[0x000F_4000..0x000F_4004].try_into().unwrap());
    let mbx_nonce = u64::from_le_bytes(flash[0x000F_4010..0x000F_4018].try_into().unwrap());
    assert_eq!(mbx_magic, 0x5842_4D54); // "TMBX"
    assert_eq!(mbx_nonce, 0xCAFE_BABE_1234_5678);
    drop(flash);

    let mut buf = [0u8; 16];
    let mut len = buf.len();
    unsafe {
        assert_eq!(
            sys::toob_os_nvs_read(c"toob_sys/cred".as_ptr(), buf.as_mut_ptr(), &mut len),
            sys::TOOB_ERR_NOT_SUPPORTED
        );
        assert_eq!(len, 0);
        assert_eq!(
            sys::toob_os_nvs_write(c"toob_sys/cred".as_ptr(), buf.as_ptr(), buf.len()),
            sys::TOOB_ERR_NOT_SUPPORTED
        );
    }
}
