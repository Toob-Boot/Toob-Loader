//
// STMicroelectronics STM32L476RG SoC Hardware Overlay for Headless Renode 1.17.0 E2E Testing
//
// Models RM0351 hardware peripherals with register-exact fidelity:
//   - BootAlias  (0x00000000): 512 KB boot alias window controlled by SYSCFG_MEMRMP.FB_MODE / BFB2
//   - OtpUid     (0x1FFF7000): 1 KB 64-bit ECC write-once OTP (+0x000..+0x3FF) & 96-bit UID (+0x590)
//   - RtcBkp     (0x40002800): 32x32-bit backup registers (BKP0R..BKP31R), gated by PWR_CR1.DBP
//   - Iwdg       (0x40003000): 32 kHz LSI Independent Watchdog latching RCC_CSR.IWDGRSTF
//   - Pwr        (0x40007000): Power control register (PWR_CR1.DBP backup domain write enable)
//   - Syscfg     (0x40010000): SYSCFG_MEMRMP (FB_MODE bit 8 latched from FLASH_OPTR.BFB2 bit 20)
//   - Rcc        (0x40021000): Clock enables & persistent RCC_CSR reset flags (BOR/PIN/SFT/IWDG/RMVF)
//   - FlashCtrl  (0x40022000): 1 MB dual-bank 2 KB-page flash (2 x 256 x 2 KB), 64-bit (72-bit SECDED
//                              ECC) write-once doubleword enforcer, OPTR.BFB2, and WRP1AR protection
//   - Rng        (0x50060800): Hardware CSPRNG (RNG_CR.RNGEN, RNG_SR.DRDY, RNG_DR)
//

using System;
using System.IO;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.Timers;
using Antmicro.Renode.Time;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class Stm32L476Rcc : IDoubleWordPeripheral, IKnownSize, IGPIOReceiver
    {
        public Stm32L476Rcc(IMachine machine)
        {
            this.machine = machine;
            csr = CsrBorRstfBit | CsrPinRstfBit | CsrLsiRdyBit;
        }

        public long Size => 0x400;

        public uint Csr
        {
            get => csr;
            set => csr = value;
        }

        public void OnGPIO(int number, bool value)
        {
            if(number == 0 && value)
            {
                csr |= CsrSftRstfBit;
                this.Log(LogLevel.Info, "SYSRESETREQ latched RCC_CSR=0x{0:X8}; requesting warm reset.", csr);
                machine.RequestReset();
            }
        }

        public void LatchWatchdogReset()
        {
            csr |= CsrIwdgRstfBit;
            this.Log(LogLevel.Info, "IWDG timeout latched RCC_CSR=0x{0:X8}; requesting warm reset.", csr);
            machine.RequestReset();
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // CR (MSIRDY | MSION | HSIRDY)
                return cr;
            case 0x08: // CFGR
                return cfgr;
            case 0x0C: // PLLCFGR
                return pllcfgr;
            case 0x48: // AHB1ENR
                return ahb1enr;
            case 0x4C: // AHB2ENR
                return ahb2enr;
            case 0x58: // APB1ENR1
                return apb1enr1;
            case 0x5C: // APB1ENR2
                return apb1enr2;
            case 0x60: // APB2ENR
                return apb2enr;
            case 0x88: // CCIPR
                return ccipr;
            case 0x94: // CSR
                return csr;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00:
                cr = value | 0x00000402U; // Keep MSIRDY & HSIRDY asserted
                break;
            case 0x08:
                cfgr = value;
                break;
            case 0x0C:
                pllcfgr = value;
                break;
            case 0x48:
                ahb1enr = value;
                break;
            case 0x4C:
                ahb2enr = value;
                break;
            case 0x58:
                apb1enr1 = value;
                break;
            case 0x5C:
                apb1enr2 = value;
                break;
            case 0x60:
                apb2enr = value;
                break;
            case 0x88:
                ccipr = value;
                break;
            case 0x94:
                if((value & CsrRmvfBit) != 0U)
                {
                    csr &= ~CsrResetFlagsMask;
                }
                csr = (csr & CsrResetFlagsMask) | (value & 0x007FFFFFU) | CsrLsiRdyBit;
                break;
            }
        }

        public void Reset()
        {
            cr = 0x00000563U;
            cfgr = 0U;
            pllcfgr = 0x00001000U;
            ahb1enr = 0x00000100U;
            ahb2enr = 0U;
            apb1enr1 = 0U;
            apb1enr2 = 0U;
            apb2enr = 0U;
            ccipr = 0U;
            // RCC_CSR reset cause flags persist across warm resets until cleared via RMVF (bit 23).
        }

        private const uint CsrLsiRdyBit = 1U << 1;
        private const uint CsrRmvfBit = 1U << 23;
        private const uint CsrPinRstfBit = 1U << 26;
        private const uint CsrBorRstfBit = 1U << 27;
        private const uint CsrSftRstfBit = 1U << 28;
        private const uint CsrIwdgRstfBit = 1U << 29;
        private const uint CsrResetFlagsMask = 0xFF000000U;

        private readonly IMachine machine;
        private uint cr = 0x00000563U;
        private uint cfgr;
        private uint pllcfgr = 0x00001000U;
        private uint ahb1enr = 0x00000100U;
        private uint ahb2enr;
        private uint apb1enr1;
        private uint apb1enr2;
        private uint apb2enr;
        private uint ccipr;
        private uint csr;
    }

    public class Stm32L476Pwr : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        public bool IsBackupWriteEnabled => (cr1 & PwrCr1DbpBit) != 0U;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // CR1
                return cr1;
            case 0x04: // CR2
                return cr2;
            case 0x10: // SR1
                return sr1;
            case 0x14: // SR2
                return sr2;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00:
                cr1 = value;
                break;
            case 0x04:
                cr2 = value;
                break;
            case 0x18: // SCR
                sr1 &= ~(value & 0x1FFU);
                break;
            }
        }

        public void Reset()
        {
            cr1 = 0x00000200U; // VOS=Range1, DBP=0 on reset per RM0351 Section 5.4.1
            cr2 = 0U;
            sr1 = 0U;
            sr2 = 0U;
        }

        private const uint PwrCr1DbpBit = 1U << 8;

        private uint cr1 = 0x00000200U;
        private uint cr2;
        private uint sr1;
        private uint sr2;
    }

    public class Stm32L476RtcBkp : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32L476RtcBkp(Stm32L476Pwr pwr = null)
        {
            this.pwr = pwr;
        }

        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            if(offset >= BkpStartOffset && offset < BkpEndOffset && ((offset & 0x3L) == 0L))
            {
                int idx = (int)((offset - BkpStartOffset) >> 2);
                return bkp[idx];
            }
            return 0U;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(offset >= BkpStartOffset && offset < BkpEndOffset && ((offset & 0x3L) == 0L))
            {
                if(pwr != null && !pwr.IsBackupWriteEnabled)
                {
                    this.Log(LogLevel.Warning, "Blocked RTC_BKP{0}R write while PWR_CR1.DBP=0", (offset - BkpStartOffset) >> 2);
                    return;
                }
                int idx = (int)((offset - BkpStartOffset) >> 2);
                bkp[idx] = value;
            }
        }

        public void Reset()
        {
            // Backup domain registers (BKP0R..BKP31R) survive software and watchdog resets.
        }

        private const long BkpStartOffset = 0x50L;
        private const long BkpEndOffset = 0xD0L;

        private readonly Stm32L476Pwr pwr;
        private readonly uint[] bkp = new uint[32];
    }

    public class Stm32L476Syscfg : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        public bool IsBank2MappedAtZero => (memRmp & FbModeBit) != 0U;

        public uint MemRmp => memRmp;

        internal void LatchBootBank(bool bank2Active)
        {
            latchedBank2 = bank2Active;
            if(bank2Active)
            {
                memRmp |= FbModeBit;
            }
            else
            {
                memRmp &= ~FbModeBit;
            }
        }

        public uint ReadDoubleWord(long offset)
        {
            if(offset == 0x00)
            {
                return memRmp;
            }
            return 0U;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(offset == 0x00)
            {
                memRmp = value & 0x00000107U;
            }
        }

        public void Reset()
        {
            memRmp = latchedBank2 ? FbModeBit : 0U;
        }

        private const uint FbModeBit = 1U << 8;

        private uint memRmp;
        private bool latchedBank2;
    }

    public class Stm32L476BootAlias : IDoubleWordPeripheral, IWordPeripheral, IBytePeripheral, IKnownSize
    {
        public Stm32L476BootAlias(MappedMemory flash, Stm32L476Syscfg syscfg = null)
        {
            this.flash = flash;
            this.syscfg = syscfg;
        }

        public long Size => BankSizeBytes;

        private long ResolveFlashOffset(long offset)
        {
            long bankBase = (syscfg != null && syscfg.IsBank2MappedAtZero) ? BankSizeBytes : 0L;
            return bankBase + (offset & (BankSizeBytes - 1L));
        }

        public uint ReadDoubleWord(long offset) => flash.ReadDoubleWord(ResolveFlashOffset(offset));
        public ushort ReadWord(long offset) => flash.ReadWord(ResolveFlashOffset(offset));
        public byte ReadByte(long offset) => flash.ReadByte(ResolveFlashOffset(offset));

        public void WriteDoubleWord(long offset, uint value) { }
        public void WriteWord(long offset, ushort value) { }
        public void WriteByte(long offset, byte value) { }
        public void Reset() { }

        private const long BankSizeBytes = 0x80000L;

        private readonly MappedMemory flash;
        private readonly Stm32L476Syscfg syscfg;
    }

    public class Stm32L476Iwdg : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32L476Iwdg(IMachine machine, Stm32L476Rcc rcc = null)
        {
            this.rcc = rcc;
            timer = new LimitTimer(
                machine.ClockSource,
                32000UL,
                this,
                "iwdg_timer",
                0xFFFUL,
                Direction.Descending,
                false,
                WorkMode.OneShot,
                true,
                false,
                4UL);
            timer.LimitReached += OnWatchdogExpired;
        }

        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x04:
                return pr;
            case 0x08:
                return rlr;
            case 0x0C:
                return 0U; // WVU=0, RVU=0, PVU=0
            case 0x10:
                return winr;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00: // KR
                uint key = value & 0xFFFFU;
                if(key == KeyUnlock)
                {
                    unlocked = true;
                }
                else if(key == KeyReload)
                {
                    unlocked = false;
                    timer.Limit = rlr;
                    timer.Value = rlr;
                    if(running)
                    {
                        timer.Enabled = true;
                    }
                }
                else if(key == KeyStart)
                {
                    unlocked = false;
                    running = true;
                    timer.Limit = rlr;
                    timer.Value = rlr;
                    timer.Enabled = true;
                }
                else
                {
                    unlocked = false;
                }
                break;
            case 0x04: // PR
                if(unlocked)
                {
                    pr = value & 0x7U;
                    int shift = (int)Math.Min(pr, 6U);
                    timer.Divider = 4UL << shift;
                }
                break;
            case 0x08: // RLR
                if(unlocked)
                {
                    rlr = value & 0xFFFU;
                    if(rlr == 0U)
                    {
                        rlr = 1U;
                    }
                    timer.Limit = rlr;
                }
                break;
            case 0x10: // WINR
                if(unlocked)
                {
                    winr = value & 0xFFFU;
                }
                break;
            }
        }

        public void Reset()
        {
            running = false;
            unlocked = false;
            pr = 0U;
            rlr = 0xFFFU;
            winr = 0xFFFU;
            timer.Enabled = false;
            timer.Divider = 4UL;
            timer.Limit = 0xFFFUL;
            timer.Value = 0xFFFUL;
        }

        private void OnWatchdogExpired()
        {
            if(!running)
            {
                return;
            }
            running = false;
            timer.Enabled = false;
            rcc?.LatchWatchdogReset();
        }

        private const uint KeyReload = 0xAAAAU;
        private const uint KeyUnlock = 0x5555U;
        private const uint KeyStart = 0xCCCCU;

        private readonly Stm32L476Rcc rcc;
        private readonly LimitTimer timer;
        private bool unlocked;
        private bool running;
        private uint pr;
        private uint rlr = 0xFFFU;
        private uint winr = 0xFFFU;
    }

    public class Stm32L476Rng : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32L476Rng()
        {
            byte[] seedBytes = Guid.NewGuid().ToByteArray();
            ulong s0 = BitConverter.ToUInt64(seedBytes, 0);
            ulong s1 = BitConverter.ToUInt64(seedBytes, 8);
            state = s0 ^ s1 ^ 0x9E3779B97F4A7C15UL;
            if(state == 0UL)
            {
                state = 0xCAFEBABEDEADBEEFUL;
            }
        }

        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // CR
                return cr;
            case 0x04: // SR
                return ((cr & RngCrEnBit) != 0U) ? RngSrDrdyBit : 0U;
            case 0x08: // DR
                if((cr & RngCrEnBit) == 0U)
                {
                    return 0U;
                }
                return DrawNonRepeatingWord();
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(offset == 0x00)
            {
                cr = value;
            }
        }

        public void Reset()
        {
            cr = 0U;
            lastSample = 0U;
        }

        private uint DrawNonRepeatingWord()
        {
            for(int i = 0; i < 8; i++)
            {
                state += 0x9E3779B97F4A7C15UL;
                ulong z = state;
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
                z ^= z >> 31;
                uint sample = (uint)(z & 0xFFFFFFFFUL);
                if(sample != 0U && sample != lastSample)
                {
                    lastSample = sample;
                    return sample;
                }
            }
            lastSample ^= 0x9E3779B9U;
            return lastSample;
        }

        private const uint RngCrEnBit = 1U << 2;
        private const uint RngSrDrdyBit = 1U << 0;

        private ulong state;
        private uint cr;
        private uint lastSample;
    }

    public class Stm32L476OtpUid : IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IKnownSize
    {
        public Stm32L476OtpUid()
        {
            ResetToDefaultErased();
        }

        public long Size => 0x800;

        internal Stm32L476FlashController FlashController { get; set; }

        public void ResetToDefaultErased()
        {
            for(int i = 0; i < OtpTotalSavedBytes; i++)
            {
                otpBytes[i] = 0xFF;
            }
            Array.Clear(otpDwordWritten, 0, otpDwordWritten.Length);
            hasPendingLowWord = false;

            byte[] defaultUid = { 0x32, 0x04, 0x76, 0x4C, 0x48, 0x33, 0x54, 0x4D, 0xAA, 0x55, 0x44, 0x76 };
            Array.Copy(defaultUid, 0, otpBytes, UidOffset, defaultUid.Length);
        }

        public void LoadBinary(string path)
        {
            ResetToDefaultErased();
            byte[] raw = File.ReadAllBytes(path);
            int len = Math.Min(raw.Length, OtpTotalSavedBytes);
            Array.Copy(raw, 0, otpBytes, 0, len);

            for(int d = 0; d < OtpDwordCount; d++)
            {
                bool anyNonErased = false;
                int baseOff = d * 8;
                for(int b = 0; b < 8; b++)
                {
                    if(otpBytes[baseOff + b] != 0xFF)
                    {
                        anyNonErased = true;
                        break;
                    }
                }
                otpDwordWritten[d] = anyNonErased;
            }
        }

        public void SaveBinary(string path)
        {
            byte[] outBytes = new byte[OtpTotalSavedBytes];
            Array.Copy(otpBytes, 0, outBytes, 0, OtpTotalSavedBytes);
            File.WriteAllBytes(path, outBytes);
        }

        public byte ReadByte(long offset)
        {
            if(offset >= 0 && offset < OtpTotalSavedBytes)
            {
                return otpBytes[offset];
            }
            return 0xFF;
        }

        public ushort ReadWord(long offset)
        {
            return (ushort)(ReadByte(offset) | (ReadByte(offset + 1) << 8));
        }

        public uint ReadDoubleWord(long offset)
        {
            return (uint)ReadByte(offset)
                 | ((uint)ReadByte(offset + 1) << 8)
                 | ((uint)ReadByte(offset + 2) << 16)
                 | ((uint)ReadByte(offset + 3) << 24);
        }

        public void WriteByte(long offset, byte value)
        {
            if(offset < 0 || offset >= OtpSizeBytes)
            {
                return;
            }
            hasPendingLowWord = false;
            FlashController?.RaiseSizErr();
        }

        public void WriteWord(long offset, ushort value)
        {
            if(offset < 0 || offset >= OtpSizeBytes)
            {
                return;
            }
            hasPendingLowWord = false;
            FlashController?.RaiseSizErr();
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(offset < 0 || offset >= OtpSizeBytes)
            {
                // 96-bit factory UID at +0x590..+0x59B and unmapped regions are read-only.
                return;
            }
            if(FlashController == null || !FlashController.IsPgEnabledAndUnlocked)
            {
                hasPendingLowWord = false;
                FlashController?.RaisePgsErr();
                return;
            }

            if(!hasPendingLowWord)
            {
                if((offset & 0x7L) != 0L)
                {
                    FlashController.RaisePgaErr();
                    return;
                }
                pendingLowOffset = offset;
                pendingLowWord = value;
                hasPendingLowWord = true;
                return;
            }

            hasPendingLowWord = false;
            if(offset != (pendingLowOffset + 4L))
            {
                FlashController.RaisePgaErr();
                return;
            }

            int dwordIdx = (int)(pendingLowOffset >> 3);

            // Check key-slot lock word if programming a 32-byte key slot (dwords 0..15)
            if(dwordIdx < 16)
            {
                int keySlot = dwordIdx / 4;
                int lockDwordIdx = 16 + keySlot;
                if(otpDwordWritten[lockDwordIdx])
                {
                    FlashController.RaiseWrpErr();
                    return;
                }
            }

            // RM0351 Section 3.3.7 / 3.3.8: 72-bit SECDED ECC forbids programming any OTP doubleword twice!
            if(otpDwordWritten[dwordIdx])
            {
                FlashController.RaiseEccDoubleWriteViolation(OtpBaseAddr + (ulong)pendingLowOffset, pendingLowWord, value);
                return;
            }

            otpDwordWritten[dwordIdx] = true;
            WriteRawLe32((int)pendingLowOffset, pendingLowWord);
            WriteRawLe32((int)offset, value);
            FlashController.RaiseEop();
        }

        private void WriteRawLe32(int byteOffset, uint val)
        {
            otpBytes[byteOffset + 0] &= (byte)(val & 0xFFU);
            otpBytes[byteOffset + 1] &= (byte)((val >> 8) & 0xFFU);
            otpBytes[byteOffset + 2] &= (byte)((val >> 16) & 0xFFU);
            otpBytes[byteOffset + 3] &= (byte)((val >> 24) & 0xFFU);
        }

        public void Reset()
        {
            // Hardware OTP, 64-bit ECC state, and factory UID persist across warm resets; clear any half-latched word.
            hasPendingLowWord = false;
        }

        private const ulong OtpBaseAddr = 0x1FFF7000UL;
        private const int OtpSizeBytes = 0x400; // 1 KB = 128 x 64-bit ECC doublewords
        private const int OtpDwordCount = 128;
        private const int UidOffset = 0x590;
        private const int OtpTotalSavedBytes = 0x5A0;

        private readonly byte[] otpBytes = new byte[OtpTotalSavedBytes];
        private readonly bool[] otpDwordWritten = new bool[OtpDwordCount];
        private bool hasPendingLowWord;
        private long pendingLowOffset;
        private uint pendingLowWord;
    }

    public class Stm32L476FlashController : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32L476FlashController(
            IMachine machine,
            MappedMemory flash,
            Stm32L476OtpUid otp = null,
            Stm32L476Syscfg syscfg = null)
        {
            this.machine = machine;
            this.flash = flash;
            this.otp = otp;
            this.syscfg = syscfg;
            if(this.otp != null)
            {
                this.otp.FlashController = this;
            }

            committedOptr = DefaultOptr;
            committedWrp1ar = DefaultWrp;
            committedWrp1br = DefaultWrp;
            committedWrp2ar = DefaultWrp;
            committedWrp2br = DefaultWrp;

            optr = committedOptr;
            wrp1ar = committedWrp1ar;
            wrp1br = committedWrp1br;
            wrp2ar = committedWrp2ar;
            wrp2br = committedWrp2br;
        }

        public long Size => 0x400;

        public uint BlockedOperations { get; private set; }

        public ulong EccDoubleWriteViolationCount { get; private set; }

        public ulong DoubleWordDoubleWriteCount => EccDoubleWriteViolationCount;

        public uint CommittedOptr
        {
            get => committedOptr;
            set
            {
                committedOptr = value;
                optr = committedOptr;
                syscfg?.LatchBootBank((committedOptr & OptrBfb2Bit) != 0U);
            }
        }

        public uint CommittedWrp1ar
        {
            get => committedWrp1ar;
            set
            {
                committedWrp1ar = value;
                wrp1ar = committedWrp1ar;
            }
        }

        internal bool IsPgEnabledAndUnlocked => ((cr & CrLockBit) == 0U) && ((cr & CrPgBit) != 0U);

        internal void RaiseWrpErr()
        {
            BlockedOperations++;
            sr |= SrWrpErrBit;
        }

        internal void RaisePgsErr()
        {
            sr |= SrPgsErrBit;
        }

        internal void RaisePgaErr()
        {
            sr |= SrPgaErrBit;
        }

        internal void RaiseSizErr()
        {
            sr |= SrSizErrBit;
        }

        internal void RaiseEccDoubleWriteViolation(ulong physAddr, uint loWord, uint hiWord)
        {
            EccDoubleWriteViolationCount++;
            sr |= SrProgErrBit;
            this.Log(
                LogLevel.Error,
                "64-bit ECC DOUBLE-WRITE VIOLATION at 0x{0:X8} (lo=0x{1:X8}, hi=0x{2:X8}, count={3})",
                physAddr,
                loWord,
                hiWord,
                EccDoubleWriteViolationCount);
        }

        internal void RaiseEop()
        {
            sr |= SrEopBit;
        }

        public void SyncEccBitmapFromFlash()
        {
            for(int d = 0; d < TotalDoubleWords; d++)
            {
                long off = (long)d * 8L;
                uint lo = flash.ReadDoubleWord(off);
                uint hi = flash.ReadDoubleWord(off + 4L);
                doubleWordWritten[d] = (lo != 0xFFFFFFFFU) || (hi != 0xFFFFFFFFU);
            }
            hasPendingLowWord = false;
            EccDoubleWriteViolationCount = 0UL;
        }

        public void InstallFlashHooks()
        {
            if(hooksInstalled)
            {
                return;
            }
            var sysbus = (SystemBus)machine.SystemBus;
            ApplyPageAccessViaIo();
            sysbus.SetHookBeforePeripheralWrite<uint>(flash, FilterWriteDoubleWord);
            sysbus.SetHookBeforePeripheralWrite<ushort>(flash, FilterWriteWord);
            sysbus.SetHookBeforePeripheralWrite<byte>(flash, FilterWriteByte);
            hooksInstalled = true;
        }

        private void ApplyPageAccessViaIo()
        {
            var sysbus = (SystemBus)machine.SystemBus;
            ulong flashLen = (ulong)flash.Size;
            for(ulong page = 0UL; page < flashLen; page += IoPageBytes)
            {
                sysbus.SetPageAccessViaIo(FlashBaseAddr + page);
            }
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // ACR
                return acr;
            case 0x10: // SR
                return sr;
            case 0x14: // CR
                return cr;
            case 0x18: // ECCR
                return eccr;
            case 0x20: // OPTR
                return optr;
            case 0x2C: // WRP1AR
                return wrp1ar;
            case 0x30: // WRP1BR
                return wrp1br;
            case 0x4C: // WRP2AR
                return wrp2ar;
            case 0x50: // WRP2BR
                return wrp2br;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00: // ACR
                acr = value;
                break;

            case 0x08: // KEYR
                if(keyState == 0 && value == FlashKey1)
                {
                    keyState = 1;
                }
                else if(keyState == 1 && value == FlashKey2)
                {
                    cr &= ~CrLockBit;
                    keyState = 0;
                }
                else
                {
                    keyState = 0;
                }
                break;

            case 0x0C: // OPTKEYR (valid only when FLASH_CR.LOCK == 0 per RM0351 Section 3.4.2)
                if((cr & CrLockBit) != 0U)
                {
                    optKeyState = 0;
                    break;
                }
                if(optKeyState == 0 && value == OptKey1)
                {
                    optKeyState = 1;
                }
                else if(optKeyState == 1 && value == OptKey2)
                {
                    cr &= ~CrOptLockBit;
                    optKeyState = 0;
                }
                else
                {
                    optKeyState = 0;
                }
                break;

            case 0x10: // SR (write-1-to-clear status & error flags)
                sr &= ~(value & SrClearMask);
                break;

            case 0x14: // CR
                if((cr & CrLockBit) != 0U)
                {
                    return;
                }

                // RM0351 Section 3.7.6: LOCK and OPTLOCK are set-only in software; writing 0 does not clear OPTLOCK.
                bool lockAfter = (value & CrLockBit) != 0U;
                bool optLockAfter = ((cr & CrOptLockBit) != 0U) || ((value & CrOptLockBit) != 0U) || lockAfter;
                bool startOpt = ((value & CrOptStrtBit) != 0U) && ((cr & CrOptLockBit) == 0U);
                bool startErase = ((value & CrStrtBit) != 0U) && ((value & CrPerBit) != 0U);

                uint nextCr = value & ~(CrStrtBit | CrOptStrtBit | CrLockBit | CrOptLockBit);
                if(optLockAfter)
                {
                    nextCr |= CrOptLockBit;
                    optKeyState = 0;
                }
                if(lockAfter)
                {
                    nextCr |= CrLockBit;
                    keyState = 0;
                    hasPendingLowWord = false;
                }
                if((nextCr & CrPgBit) == 0U)
                {
                    hasPendingLowWord = false;
                }
                cr = nextCr;

                if(startOpt)
                {
                    committedOptr = optr;
                    committedWrp1ar = wrp1ar;
                    committedWrp1br = wrp1br;
                    committedWrp2ar = wrp2ar;
                    committedWrp2br = wrp2br;
                    syscfg?.LatchBootBank((committedOptr & OptrBfb2Bit) != 0U);
                    sr |= SrEopBit;
                }

                if(startErase)
                {
                    uint bank = ((value & CrBkerBit) != 0U) ? 1U : 0U;
                    uint pnb = (value >> CrPnbShift) & 0xFFU;
                    HandlePageErase(bank, pnb);
                }
                break;

            case 0x18: // ECCR
                eccr &= ~(value & 0xC0000000U);
                break;

            case 0x20: // OPTR
                if((cr & CrOptLockBit) == 0U)
                {
                    optr = value;
                }
                break;

            case 0x2C: // WRP1AR
                if((cr & CrOptLockBit) == 0U)
                {
                    wrp1ar = (value & 0x00FF00FFU) | 0xFF00FF00U;
                }
                break;

            case 0x30: // WRP1BR
                if((cr & CrOptLockBit) == 0U)
                {
                    wrp1br = (value & 0x00FF00FFU) | 0xFF00FF00U;
                }
                break;

            case 0x4C: // WRP2AR
                if((cr & CrOptLockBit) == 0U)
                {
                    wrp2ar = (value & 0x00FF00FFU) | 0xFF00FF00U;
                }
                break;

            case 0x50: // WRP2BR
                if((cr & CrOptLockBit) == 0U)
                {
                    wrp2br = (value & 0x00FF00FFU) | 0xFF00FF00U;
                }
                break;
            }
        }

        public void Reset()
        {
            acr = 0x00000600U; // ICEN | DCEN default enabled on reset per RM0351 Section 3.7.1
            sr = 0U;
            cr = CrLockBit | CrOptLockBit;
            eccr = 0U;
            keyState = 0;
            optKeyState = 0;
            hasPendingLowWord = false;

            optr = committedOptr;
            wrp1ar = committedWrp1ar;
            wrp1br = committedWrp1br;
            wrp2ar = committedWrp2ar;
            wrp2br = committedWrp2br;

            syscfg?.LatchBootBank((committedOptr & OptrBfb2Bit) != 0U);
            if(hooksInstalled)
            {
                ApplyPageAccessViaIo();
            }
            // Note: doubleWordWritten[] and EccDoubleWriteViolationCount persist across warm resets!
        }

        private void HandlePageErase(uint bank, uint pnb)
        {
            if(bank > 1U || pnb >= PagesPerBank)
            {
                sr |= SrPgsErrBit;
                return;
            }

            if(IsPageWriteProtected(bank, pnb))
            {
                BlockedOperations++;
                sr |= SrWrpErrBit;
                this.Log(LogLevel.Warning, "WRP blocked 2 KB page erase on bank {0} page {1}", bank, pnb);
                return;
            }

            long pageOffset = ((long)bank * BankSizeBytes) + ((long)pnb * FlashPageSizeBytes);
            flash.SetRange(pageOffset, FlashPageSizeBytes, 0xFF);

            int firstDword = (int)(pageOffset >> 3);
            Array.Clear(doubleWordWritten, firstDword, DwordsPerFlashPage);
            sr |= SrEopBit;
        }

        private bool IsPageWriteProtected(uint bank, uint pageInBank)
        {
            if(bank == 0U)
            {
                return IsPageInWrpWindow(committedWrp1ar, pageInBank)
                    || IsPageInWrpWindow(committedWrp1br, pageInBank);
            }
            return IsPageInWrpWindow(committedWrp2ar, pageInBank)
                || IsPageInWrpWindow(committedWrp2br, pageInBank);
        }

        private static bool IsPageInWrpWindow(uint wrpReg, uint page)
        {
            uint strt = wrpReg & 0xFFU;
            uint end = (wrpReg >> 16) & 0xFFU;
            return (strt <= end) && (page >= strt) && (page <= end);
        }

        private uint FilterWriteDoubleWord(uint value, long offset)
        {
            uint existing = flash.ReadDoubleWord(offset);
            if(offset < 0L || offset >= flash.Size)
            {
                return existing;
            }
            if(!IsPgEnabledAndUnlocked)
            {
                hasPendingLowWord = false;
                sr |= SrPgsErrBit;
                return existing;
            }

            if(!hasPendingLowWord)
            {
                if((offset & 0x7L) != 0L)
                {
                    sr |= SrPgaErrBit;
                    return existing;
                }
                pendingLowOffset = offset;
                pendingLowWord = value;
                hasPendingLowWord = true;
                return existing;
            }

            hasPendingLowWord = false;
            if(offset != (pendingLowOffset + 4L))
            {
                sr |= SrPgaErrBit;
                return existing;
            }

            uint bank = (pendingLowOffset >= BankSizeBytes) ? 1U : 0U;
            uint pageInBank = (uint)((pendingLowOffset - ((long)bank * BankSizeBytes)) / FlashPageSizeBytes);
            if(IsPageWriteProtected(bank, pageInBank))
            {
                BlockedOperations++;
                sr |= SrWrpErrBit;
                this.Log(LogLevel.Warning, "WRP blocked 64-bit flash program at +0x{0:X6} (bank {1}, page {2})", pendingLowOffset, bank, pageInBank);
                return existing;
            }

            int dwordIdx = (int)(pendingLowOffset >> 3);
            if(doubleWordWritten[dwordIdx])
            {
                RaiseEccDoubleWriteViolation(FlashBaseAddr + (ulong)pendingLowOffset, pendingLowWord, value);
                return existing;
            }

            doubleWordWritten[dwordIdx] = true;
            uint existingLow = flash.ReadDoubleWord(pendingLowOffset);
            flash.WriteDoubleWord(pendingLowOffset, existingLow & pendingLowWord);
            sr |= SrEopBit;
            return existing & value;
        }

        private ushort FilterWriteWord(ushort value, long offset)
        {
            hasPendingLowWord = false;
            sr |= SrSizErrBit;
            return flash.ReadWord(offset);
        }

        private byte FilterWriteByte(byte value, long offset)
        {
            hasPendingLowWord = false;
            sr |= SrSizErrBit;
            return flash.ReadByte(offset);
        }

        private const ulong FlashBaseAddr = 0x08000000UL;
        private const ulong IoPageBytes = 0x1000UL;
        private const long BankSizeBytes = 0x80000L; // 512 KB per bank
        private const long FlashPageSizeBytes = 0x800L; // 2 KB per page
        private const uint PagesPerBank = 256U;
        private const int DwordsPerFlashPage = 256; // 2048 / 8
        private const int TotalDoubleWords = 131072; // 1 MB / 8

        private const uint FlashKey1 = 0x45670123U;
        private const uint FlashKey2 = 0xCDEF89ABU;
        private const uint OptKey1 = 0x08192A3BU;
        private const uint OptKey2 = 0x4C5D6E7FU;

        private const uint SrEopBit = 1U << 0;
        private const uint SrProgErrBit = 1U << 3;
        private const uint SrWrpErrBit = 1U << 4;
        private const uint SrPgaErrBit = 1U << 5;
        private const uint SrSizErrBit = 1U << 6;
        private const uint SrPgsErrBit = 1U << 7;
        private const uint SrClearMask = 0x0000C3FBU;

        private const uint CrPgBit = 1U << 0;
        private const uint CrPerBit = 1U << 1;
        private const int CrPnbShift = 3;
        private const uint CrBkerBit = 1U << 11;
        private const uint CrStrtBit = 1U << 16;
        private const uint CrOptStrtBit = 1U << 17;
        private const uint CrOptLockBit = 1U << 30;
        private const uint CrLockBit = 1U << 31;

        private const uint OptrBfb2Bit = 1U << 20;
        private const uint DefaultOptr = 0xFFEFF8AAU; // DUALBANK=1, BFB2=0, RDP=0xAA
        private const uint DefaultWrp = 0xFF00FFFFU;  // STRT=0xFF > END=0x00 (unprotected)

        private readonly IMachine machine;
        private readonly MappedMemory flash;
        private readonly Stm32L476OtpUid otp;
        private readonly Stm32L476Syscfg syscfg;
        private readonly bool[] doubleWordWritten = new bool[TotalDoubleWords];

        private bool hooksInstalled;
        private int keyState;
        private int optKeyState;
        private bool hasPendingLowWord;
        private long pendingLowOffset;
        private uint pendingLowWord;

        private uint acr = 0x00000600U;
        private uint sr;
        private uint cr = CrLockBit | CrOptLockBit;
        private uint eccr;
        private uint optr;
        private uint wrp1ar;
        private uint wrp1br;
        private uint wrp2ar;
        private uint wrp2br;

        private uint committedOptr;
        private uint committedWrp1ar;
        private uint committedWrp1br;
        private uint committedWrp2ar;
        private uint committedWrp2br;
    }
}

