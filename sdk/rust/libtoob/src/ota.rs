use crate::{Result, ToobError, ToobStatusExt};
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
    pub fn begin_verified(
        mut self,
        total_size: u32,
        expected_hash: &[u8; 32],
    ) -> Result<OtaSession<Receiving>> {
        unsafe {
            sys::toob_ota_begin(&mut self.ctx, total_size, expected_hash.as_ptr()).to_result()?;
        }
        Ok(OtaSession {
            ctx: self.ctx,
            _state: core::marker::PhantomData,
        })
    }

    /// Begin a new verified update bound to a 16-byte campaign assignment UUID.
    pub fn begin_assigned(
        mut self,
        total_size: u32,
        expected_hash: &[u8; 32],
        assignment_id: &[u8; 16],
    ) -> Result<OtaSession<Receiving>> {
        unsafe {
            sys::toob_ota_begin_assigned(
                &mut self.ctx,
                total_size,
                expected_hash.as_ptr(),
                assignment_id.as_ptr(),
            )
            .to_result()?;
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
            sys::toob_ota_resume(&mut self.ctx, total_size, core::ptr::null(), &mut offset)
                .to_result()?;
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
    pub fn resume_verified(
        mut self,
        total_size: u32,
        expected_hash: &[u8; 32],
    ) -> Result<(OtaSession<Receiving>, u32)> {
        let mut offset = 0u32;
        unsafe {
            sys::toob_ota_resume(&mut self.ctx, total_size, expected_hash.as_ptr(), &mut offset)
                .to_result()?;
        }
        Ok((
            OtaSession {
                ctx: self.ctx,
                _state: core::marker::PhantomData,
            },
            offset,
        ))
    }

    /// Resume an interrupted verified OTA download only if the checkpoint matches `assignment_id`.
    pub fn resume_assigned(
        mut self,
        total_size: u32,
        expected_hash: &[u8; 32],
        expected_assignment_id: &[u8; 16],
    ) -> Result<(OtaSession<Receiving>, u32)> {
        let mut offset = 0u32;
        unsafe {
            sys::toob_ota_resume_assigned(
                &mut self.ctx,
                total_size,
                expected_hash.as_ptr(),
                expected_assignment_id.as_ptr(),
                &mut offset,
            )
            .to_result()?;
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
        if chunk.is_empty() {
            return Err(ToobError::InvalidArg);
        }
        let len = u32::try_from(chunk.len()).map_err(|_| ToobError::InvalidArg)?;
        unsafe {
            sys::toob_ota_process_chunk(&mut self.ctx, chunk.as_ptr(), len).to_result()?;
        }
        Ok(())
    }

    /// Shrinks the upper-bound `total_size` once exact payload length is discovered.
    pub fn trim_total_size(&mut self, exact_total_size: u32) -> Result<()> {
        unsafe {
            sys::toob_ota_trim_total_size(&mut self.ctx, exact_total_size).to_result()?;
        }
        Ok(())
    }

    /// Pause the OTA session on transient transport loss, zeroizing sensitive RAM
    /// while preserving the .noinit resume checkpoint.
    pub fn pause(mut self) -> OtaSession<Idle> {
        unsafe {
            let _ = sys::toob_ota_pause(&mut self.ctx);
        }
        OtaSession {
            ctx: self.ctx,
            _state: core::marker::PhantomData,
        }
    }

    /// Abort the OTA session, securely cleaning up RAM state and clearing checkpoints.
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
