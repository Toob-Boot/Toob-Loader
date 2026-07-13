use crate::{Result, ToobStatusExt};
use libtoob_sys as sys;

pub struct OtaSession<S> {
    ctx: sys::toob_ota_ctx_t,
    _state: core::marker::PhantomData<S>,
}

// Marker States
pub struct Idle;
pub struct Receiving;
pub struct Done;

impl OtaSession<Idle> {
    /// Initialize a new inactive OTA session.
    pub fn new() -> Result<Self> {
        let mut ctx = unsafe { core::mem::zeroed() };
        unsafe {
            sys::toob_ota_ctx_init(&mut ctx).to_result()?;
        }
        Ok(Self {
            ctx,
            _state: core::marker::PhantomData,
        })
    }

    /// Begin a new unverified OTA update.
    pub fn begin(mut self, total_size: u32) -> Result<OtaSession<Receiving>> {
        unsafe {
            sys::toob_ota_begin(&mut self.ctx, total_size, core::ptr::null()).to_result()?;
        }
        Ok(OtaSession {
            ctx: self.ctx,
            _state: core::marker::PhantomData,
        })
    }

    /// Begin a new update verified by a streaming SHA-256 hash.
    pub fn begin_verified(mut self, total_size: u32, expected_hash: &[u8; 32]) -> Result<OtaSession<Receiving>> {
        unsafe {
            sys::toob_ota_begin(&mut self.ctx, total_size, expected_hash.as_ptr()).to_result()?;
        }
        Ok(OtaSession {
            ctx: self.ctx,
            _state: core::marker::PhantomData,
        })
    }

    /// Resume an interrupted unverified OTA download.
    pub fn resume(mut self, total_size: u32) -> Result<(OtaSession<Receiving>, u32)> {
        let mut offset = 0u32;
        unsafe {
            sys::toob_ota_resume(&mut self.ctx, total_size, core::ptr::null(), &mut offset).to_result()?;
        }
        Ok((
            OtaSession {
                ctx: self.ctx,
                _state: core::marker::PhantomData,
            },
            offset,
        ))
    }

    /// Resume an interrupted verified OTA download.
    pub fn resume_verified(mut self, total_size: u32, expected_hash: &[u8; 32]) -> Result<(OtaSession<Receiving>, u32)> {
        let mut offset = 0u32;
        unsafe {
            sys::toob_ota_resume(&mut self.ctx, total_size, expected_hash.as_ptr(), &mut offset).to_result()?;
        }
        Ok((
            OtaSession {
                ctx: self.ctx,
                _state: core::marker::PhantomData,
            },
            offset,
        ))
    }
}

impl OtaSession<Receiving> {
    /// Feed a chunk of incoming download payload into the stream buffer.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        unsafe {
            sys::toob_ota_process_chunk(&mut self.ctx, chunk.as_ptr(), chunk.len() as u32).to_result()?;
        }
        Ok(())
    }

    /// Abort the OTA session, securely cleaning up all internal state.
    pub fn abort(mut self) -> OtaSession<Idle> {
        unsafe {
            let _ = sys::toob_ota_abort(&mut self.ctx);
        }
        OtaSession {
            ctx: self.ctx,
            _state: core::marker::PhantomData,
        }
    }

    /// Complete download phase and transition to finalize sequence.
    pub fn finalize(mut self) -> Result<OtaSession<Done>> {
        unsafe {
            sys::toob_ota_finalize(&mut self.ctx).to_result()?;
        }
        Ok(OtaSession {
            ctx: self.ctx,
            _state: core::marker::PhantomData,
        })
    }
}
