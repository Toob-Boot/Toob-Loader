//
// STMicroelectronics STM32H753ZI SoC Hardware Overlay for Headless Renode 1.17.0 E2E Testing
//
// Models RM0433 + ARMv7E-M Cortex-M7 hardware peripherals with register-exact fidelity:
//   - OtpUid     (0x1FF1E000): 512B OTP (16x32B, 1->0), 16B OTP lock bytes (+0x200), 96-bit UID (+0x800)
//   - Rng        (0x48021800): Hardware TRNG (RNG_CR.RNGEN, RNG_SR.DRDY, RNG_DR)
//   - FlashCtrl  (0x52002000): Dual-Bank 256-Bit (32-Byte) SECDED ECC Flash Controller (Bank 1 +0x000,
//                              Bank 2 +0x100, SWAP_BANK_OPT, WPSN1R/WPSN2R active-low sector write
//                              protection, and strict 32-Byte Flash-Word ECC Write-Once Enforcer across
//                              all 98,304 Flash-Words in 0x08000000..0x082FFFFF)
//   - ScbCache   (0xE000ED14..0xE000EF74 via NVIC bus hooks): Cortex-M7 L1 I$/D$ Cache Control &
//                              Maintenance (CCR.IC, CCR.DC, CCSIDR, CSSELR, ICIALLU, DCISW, DCCIMVAC, DCCISW)
//   - RtcBkp     (0x58004000): 32x32-bit backup registers (BKP0R..BKP31R at +0x50), gated by PWR_CR1.DBP
//   - Iwdg1      (0x58004800): 32 kHz LSI Independent Watchdog 1 latching RCC_RSR.IWDG1RSTF
//   - Rcc        (0x58024400): Clock enables & persistent RCC_RSR (+0xD0) reset flags (POR/PIN/SFT/IWDG1/RMVF)
//   - Pwr        (0x58024800): Power control register 1 (PWR_CR1.DBP backup domain write enable)
//

using System;
using System.IO;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.IRQControllers;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.Timers;
using Antmicro.Renode.Time;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class Stm32H753Rcc : IDoubleWordPeripheral, IKnownSize, IGPIOReceiver
    {
        public Stm32H753Rcc(IMachine machine)
        {
            this.machine = machine;
            rsr = RsrPorRstfBit | RsrPinRstfBit;
        }

        public long Size => 0x400;

        public uint Rsr
        {
            get => rsr;
            set => rsr = value;
        }

        public void OnGPIO(int number, bool value)
        {
            if(number == 0 && value)
            {
                rsr |= RsrSftRstfBit;
                this.Log(LogLevel.Info, "SYSRESETREQ latched RCC_RSR=0x{0:X8}; requesting warm reset.", rsr);
                machine.RequestReset();
            }
        }

        public void LatchWatchdogReset()
        {
            rsr |= RsrIwdg1RstfBit;
            this.Log(LogLevel.Info, "IWDG1 timeout latched RCC_RSR=0x{0:X8}; requesting warm reset.", rsr);
            machine.RequestReset();
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // CR (HSIRDY | HSION)
                return cr;
            case 0xD0: // RSR
                return rsr;
            case 0xDC: // AHB2ENR
                return ahb2enr;
            case 0xF0: // APB2ENR
                return apb2enr;
            case 0xF4: // APB4ENR
                return apb4enr;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00:
                cr = value | 0x00000005U;
                break;
            case 0xD0: // RSR
                if((value & RsrRmvfBit) != 0U)
                {
                    rsr &= ~RsrResetFlagsMask;
                }
                break;
            case 0xDC:
                ahb2enr = value;
                break;
            case 0xF0:
                apb2enr = value;
                break;
            case 0xF4:
                apb4enr = value;
                break;
            }
        }

        public void Reset()
        {
            cr = 0x00000005U;
            ahb2enr = 0U;
            apb2enr = 0U;
            apb4enr = 0U;
            // RCC_RSR reset cause flags persist across warm resets until cleared via RMVF.
        }

        private const uint RsrRmvfBit = 1U << 16;
        private const uint RsrBorRstfBit = 1U << 21;
        private const uint RsrPinRstfBit = 1U << 22;
        private const uint RsrPorRstfBit = 1U << 23;
        private const uint RsrSftRstfBit = 1U << 24;
        private const uint RsrIwdg1RstfBit = 1U << 26;
        private const uint RsrWwdg1RstfBit = 1U << 28;
        private const uint RsrLpwrRstfBit = 1U << 30;
        private const uint RsrResetFlagsMask = RsrBorRstfBit | RsrPinRstfBit | RsrPorRstfBit |
                                               RsrSftRstfBit | RsrIwdg1RstfBit | RsrWwdg1RstfBit |
                                               RsrLpwrRstfBit;

        private readonly IMachine machine;
        private uint cr = 0x00000005U;
        private uint rsr;
        private uint ahb2enr;
        private uint apb2enr;
        private uint apb4enr;
    }

    public class Stm32H753Pwr : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        public bool IsBackupWriteEnabled => (cr1 & PwrCr1DbpBit) != 0U;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00:
                return cr1;
            case 0x04:
                return csr1;
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
                csr1 = value;
                break;
            }
        }

        public void Reset()
        {
            cr1 = 0x0000F000U; // DBP = 0 on reset per RM0433 Section 7.8.1
            csr1 = 0x00004000U;
        }

        private const uint PwrCr1DbpBit = 1U << 8;

        private uint cr1 = 0x0000F000U;
        private uint csr1 = 0x00004000U;
    }

    public class Stm32H753RtcBkp : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32H753RtcBkp(Stm32H753Pwr pwr = null)
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
            // Backup domain registers survive software and watchdog resets.
        }

        private const long BkpStartOffset = 0x50L;
        private const long BkpEndOffset = 0xD0L;

        private readonly Stm32H753Pwr pwr;
        private readonly uint[] bkp = new uint[32];
    }

    public class Stm32H753Iwdg : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32H753Iwdg(IMachine machine, Stm32H753Rcc rcc = null)
        {
            this.rcc = rcc;
            timer = new LimitTimer(
                machine.ClockSource,
                32000UL,
                this,
                "iwdg1_timer",
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
            }
        }

        public void Reset()
        {
            running = false;
            unlocked = false;
            pr = 0U;
            rlr = 0xFFFU;
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

        private readonly Stm32H753Rcc rcc;
        private readonly LimitTimer timer;
        private bool unlocked;
        private bool running;
        private uint pr;
        private uint rlr = 0xFFFU;
    }

    public class Stm32H753Rng : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32H753Rng()
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

    public class Stm32H753OtpUid : IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IKnownSize
    {
        public Stm32H753OtpUid()
        {
            ResetToDefaultErased();
        }

        public long Size => 0x1000;

        internal Stm32H753FlashController FlashController { get; set; }

        public void ResetToDefaultErased()
        {
            for(int i = 0; i < OtpTotalSavedBytes; i++)
            {
                otpBytes[i] = 0xFF;
            }
            byte[] defaultUid = { 0x32, 0x07, 0x53, 0x00, 0x48, 0x37, 0x54, 0x4D, 0xCC, 0x77, 0x33, 0x44 };
            Array.Copy(defaultUid, 0, otpBytes, UidOffset, defaultUid.Length);
        }

        public void LoadBinary(string path)
        {
            ResetToDefaultErased();
            byte[] raw = File.ReadAllBytes(path);
            int len = Math.Min(raw.Length, OtpTotalSavedBytes);
            Array.Copy(raw, 0, otpBytes, 0, len);
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
            if(offset < 0 || offset >= OtpEditableLimit)
            {
                // 96-bit factory UID at +0x800..+0x80B and reserved bytes are read-only.
                return;
            }
            if(FlashController == null || !FlashController.IsBank1PgEnabledAndUnlocked)
            {
                FlashController?.RaiseBank1PgsErr();
                return;
            }

            if(offset < OtpLockOffset)
            {
                int block = (int)(offset / OtpBlockBytes);
                byte lockByte = otpBytes[OtpLockOffset + block];
                if(lockByte == 0x00)
                {
                    FlashController.RaiseBank1WrpErr();
                    return;
                }
                otpBytes[offset] &= value;
                FlashController.RaiseBank1Eop();
                return;
            }

            // OTP Lock bytes (+0x200..+0x20F): 1->0 irreversible lock
            otpBytes[offset] &= value;
            FlashController.RaiseBank1Eop();
        }

        public void WriteWord(long offset, ushort value)
        {
            WriteByte(offset, (byte)(value & 0xFFU));
            WriteByte(offset + 1, (byte)((value >> 8) & 0xFFU));
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            WriteByte(offset, (byte)(value & 0xFFU));
            WriteByte(offset + 1, (byte)((value >> 8) & 0xFFU));
            WriteByte(offset + 2, (byte)((value >> 16) & 0xFFU));
            WriteByte(offset + 3, (byte)((value >> 24) & 0xFFU));
        }

        public void Reset()
        {
            // Hardware OTP, OTP lock bytes, and factory UID persist across all resets.
        }

        private const int OtpBlockBytes = 32;
        private const int OtpLockOffset = 0x200;
        private const int OtpEditableLimit = 0x210;
        private const int UidOffset = 0x800;
        private const int OtpTotalSavedBytes = 0x810;

        private readonly byte[] otpBytes = new byte[OtpTotalSavedBytes];
    }

    public class Stm32H753FlashController : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32H753FlashController(
            IMachine machine,
            MappedMemory flash,
            Stm32H753OtpUid otp = null,
            NVIC nvic = null)
        {
            this.machine = machine;
            this.flash = flash;
            this.otp = otp;
            this.nvic = nvic;
            if(this.otp != null)
            {
                this.otp.FlashController = this;
            }

            totalFlashWords = (int)(flash.Size / FlashWordBytes);
            flashWordWritten = new bool[totalFlashWords];
            flashWordStrobeMask = new byte[totalFlashWords];

            committedOptsr = DefaultOptsr;
            optsrPrg = DefaultOptsr;
            committedWpsn1r = DefaultWpsn;
            wpsnPrg1r = DefaultWpsn;
            committedWpsn2r = DefaultWpsn;
            wpsnPrg2r = DefaultWpsn;
            optcr = OptLockBit;
        }

        public long Size => 0x400;

        public uint BlockedOperations { get; private set; }

        public uint FlashWordDoubleWriteCount { get; private set; }

        public uint CommittedOptsr => committedOptsr;

        public bool SwapBankCommitted => (committedOptsr & OptsrSwapBankOptBit) != 0U;

        public uint CommittedWpsn1r => committedWpsn1r;

        public uint CommittedWpsn2r => committedWpsn2r;

        public bool ICacheEnabled => (scbCcrCacheBits & ScbCcrIcBit) != 0U;

        public bool DCacheEnabled => (scbCcrCacheBits & ScbCcrDcBit) != 0U;

        public uint ICacheInvalidateCount { get; private set; }

        public uint DCacheInitInvalidateCount { get; private set; }

        public uint DCacheCleanInvalidateCount { get; private set; }

        public uint DCacheRangeCleanInvalidateCount { get; private set; }

        public bool HandoffCacheCoherent { get; private set; }

        public uint HandoffCount { get; private set; }

        public uint UncoherentHandoffCount { get; private set; }

        internal bool IsBank1PgEnabledAndUnlocked => ((cr1 & CrLockBit) == 0U) && ((cr1 & CrPgBit) != 0U);

        internal void RaiseBank1WrpErr()
        {
            BlockedOperations++;
            sr1 |= SrWrpErrBit;
        }

        internal void RaiseBank1PgsErr()
        {
            sr1 |= SrPgsErrBit;
        }

        internal void RaiseBank1Eop()
        {
            sr1 |= SrEopBit;
        }

        public void InstallFlashHooks()
        {
            if(hooksInstalled)
            {
                return;
            }
            var sysbus = (SystemBus)machine.SystemBus;
            SeedPreloadedFlashWords();
            ApplyPageAccessViaIo();
            sysbus.SetHookBeforePeripheralWrite<uint>(flash, FilterWriteDoubleWord);
            sysbus.SetHookBeforePeripheralWrite<ushort>(flash, FilterWriteWord);
            sysbus.SetHookBeforePeripheralWrite<byte>(flash, FilterWriteByte);

            if(nvic != null)
            {
                sysbus.SetHookAfterPeripheralRead<uint>(nvic, FilterNvicRead);
                sysbus.SetHookBeforePeripheralWrite<uint>(nvic, FilterNvicWrite);
            }
            hooksInstalled = true;
        }

        private void SeedPreloadedFlashWords()
        {
            for(int fw = 0; fw < totalFlashWords; fw++)
            {
                long baseOff = (long)fw * FlashWordBytes;
                bool anyProgrammed = false;
                for(int w = 0; w < 8; w++)
                {
                    if(flash.ReadDoubleWord(baseOff + (w * 4L)) != 0xFFFFFFFFU)
                    {
                        anyProgrammed = true;
                        break;
                    }
                }
                flashWordWritten[fw] = anyProgrammed;
                flashWordStrobeMask[fw] = anyProgrammed ? (byte)0xFF : (byte)0x00;
            }
            activeFwBank1 = -1;
            activeFwBank2 = -1;
            lastDoubleWriteFwBank1 = -1;
            lastDoubleWriteFwBank2 = -1;
        }

        private void ApplyPageAccessViaIo()
        {
            var sysbus = (SystemBus)machine.SystemBus;
            ulong flashLen = (ulong)flash.Size;
            for(ulong page = 0UL; page < flashLen; page += PageSizeBytes)
            {
                sysbus.SetPageAccessViaIo(FlashBaseAddr + page);
            }
        }

        private uint FilterNvicRead(uint value, long offset)
        {
            switch(offset)
            {
            case ScbCcrOffset:
                return value | scbCcrCacheBits;
            case ScbCcsidrOffset:
                // 4 KB 4-way set-associative L1 cache (32 sets, 4 ways, 32-byte line size)
                return ScbCcsidrValue;
            case ScbCsselrOffset:
                return scbCsselr;
            default:
                return value;
            }
        }

        private uint FilterNvicWrite(uint value, long offset)
        {
            switch(offset)
            {
            case ScbVtorOffset:
                // Audit cache coherency at exact Stage 1 -> Guest App / Recovery OS VTOR handoff
                if(lastVtor < OsPartitionMinVtor && value >= OsPartitionMinVtor)
                {
                    bool coherent = !flashDirtySinceSync && ICacheEnabled && DCacheEnabled;
                    HandoffCacheCoherent = coherent;
                    HandoffCount++;
                    if(!coherent)
                    {
                        UncoherentHandoffCount++;
                    }
                }
                lastVtor = value;
                break;
            case ScbCcrOffset:
                scbCcrCacheBits = value & (ScbCcrIcBit | ScbCcrDcBit);
                break;
            case ScbCsselrOffset:
                scbCsselr = value & 0xFU;
                break;
            case ScbIcialluOffset:
                ICacheInvalidateCount++;
                if(dcacheCleanedSinceMutation || !flashDirtySinceSync)
                {
                    flashDirtySinceSync = false;
                }
                break;
            case ScbDciswOffset:
                if(value == FinalSetWayValue)
                {
                    DCacheInitInvalidateCount++;
                }
                break;
            case ScbDccimvacOffset:
                DCacheRangeCleanInvalidateCount++;
                break;
            case ScbDcciswOffset:
                if(value == FinalSetWayValue)
                {
                    DCacheCleanInvalidateCount++;
                    dcacheCleanedSinceMutation = true;
                }
                break;
            }
            return value;
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // ACR
                return acr;
            case 0x00C: // CR1
                return cr1;
            case 0x010: // SR1
                return sr1;
            case 0x018: // OPTCR
                return optcr;
            case 0x01C: // OPTSR_CUR
                return committedOptsr & ~OptsrOptBusyBit;
            case 0x020: // OPTSR_PRG
                return optsrPrg;
            case 0x038: // WPSN_CUR1R
                return committedWpsn1r;
            case 0x03C: // WPSN_PRG1R
                return wpsnPrg1r;
            case 0x10C: // CR2
                return cr2;
            case 0x110: // SR2
                return sr2;
            case 0x138: // WPSN_CUR2R
                return committedWpsn2r;
            case 0x13C: // WPSN_PRG2R
                return wpsnPrg2r;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x000: // ACR
                acr = value;
                break;

            case 0x004: // KEYR1
                if(keyState1 == 0 && value == FlashKey1)
                {
                    keyState1 = 1;
                }
                else if(keyState1 == 1 && value == FlashKey2)
                {
                    cr1 &= ~CrLockBit;
                    keyState1 = 0;
                }
                else
                {
                    keyState1 = 0;
                }
                break;

            case 0x008: // OPTKEYR
                if(optKeyState == 0 && value == OptKey1)
                {
                    optKeyState = 1;
                }
                else if(optKeyState == 1 && value == OptKey2)
                {
                    optcr &= ~OptLockBit;
                    optKeyState = 0;
                }
                else
                {
                    optKeyState = 0;
                }
                break;

            case 0x00C: // CR1
                HandleBankCrWrite(isBank1: true, value);
                break;

            case 0x014: // CCR1 (write-1-to-clear SR1 flags)
                if((value & SrIncErrBit) != 0U)
                {
                    lastDoubleWriteFwBank1 = -1;
                }
                sr1 &= ~(value & CcrClearMask);
                break;

            case 0x018: // OPTCR
                if((optcr & OptLockBit) != 0U)
                {
                    return;
                }
                bool lockAfter = (value & OptLockBit) != 0U;
                bool startOpt = (value & OptStartBit) != 0U;
                optcr = value & ~OptStartBit;
                if(startOpt)
                {
                    committedOptsr = optsrPrg & ~OptsrOptBusyBit;
                    committedWpsn1r = wpsnPrg1r & WpsnMask;
                    committedWpsn2r = wpsnPrg2r & WpsnMask;
                    sr1 |= SrEopBit;
                }
                if(lockAfter)
                {
                    optcr |= OptLockBit;
                    optKeyState = 0;
                }
                break;

            case 0x020: // OPTSR_PRG
                if((optcr & OptLockBit) == 0U)
                {
                    optsrPrg = value & ~OptsrOptBusyBit;
                }
                break;

            case 0x03C: // WPSN_PRG1R
                if((optcr & OptLockBit) == 0U)
                {
                    wpsnPrg1r = value & WpsnMask;
                }
                break;

            case 0x104: // KEYR2
                if(keyState2 == 0 && value == FlashKey1)
                {
                    keyState2 = 1;
                }
                else if(keyState2 == 1 && value == FlashKey2)
                {
                    cr2 &= ~CrLockBit;
                    keyState2 = 0;
                }
                else
                {
                    keyState2 = 0;
                }
                break;

            case 0x10C: // CR2
                HandleBankCrWrite(isBank1: false, value);
                break;

            case 0x114: // CCR2 (write-1-to-clear SR2 flags)
                if((value & SrIncErrBit) != 0U)
                {
                    lastDoubleWriteFwBank2 = -1;
                }
                sr2 &= ~(value & CcrClearMask);
                break;

            case 0x13C: // WPSN_PRG2R
                if((optcr & OptLockBit) == 0U)
                {
                    wpsnPrg2r = value & WpsnMask;
                }
                break;
            }
        }

        public void Reset()
        {
            SealActiveFlashWord(isBank1: true);
            SealActiveFlashWord(isBank1: false);
            lastDoubleWriteFwBank1 = -1;
            lastDoubleWriteFwBank2 = -1;

            acr = DefaultAcr;
            sr1 = 0U;
            sr2 = 0U;
            cr1 = CrLockBit;
            cr2 = CrLockBit;
            keyState1 = 0;
            keyState2 = 0;
            optKeyState = 0;
            optcr = OptLockBit;
            optsrPrg = committedOptsr;
            wpsnPrg1r = committedWpsn1r;
            wpsnPrg2r = committedWpsn2r;

            // Cortex-M7 L1 I$/D$ caches reset disabled (CCR.IC=0, CCR.DC=0) until startup.c re-enables them.
            scbCcrCacheBits = 0U;
            scbCsselr = 0U;
            lastVtor = 0x08000000U;

            if(hooksInstalled)
            {
                ApplyPageAccessViaIo();
            }
        }

        private void HandleBankCrWrite(bool isBank1, uint value)
        {
            uint curCr = isBank1 ? cr1 : cr2;
            if((curCr & CrLockBit) != 0U)
            {
                return;
            }

            if((value & CrLockBit) != 0U || (value & CrPgBit) == 0U)
            {
                SealActiveFlashWord(isBank1);
                if(isBank1)
                {
                    lastDoubleWriteFwBank1 = -1;
                }
                else
                {
                    lastDoubleWriteFwBank2 = -1;
                }
            }

            if((value & CrLockBit) != 0U)
            {
                uint lockedVal = (value & ~CrStartBit) | CrLockBit;
                if(isBank1)
                {
                    cr1 = lockedVal;
                    keyState1 = 0;
                }
                else
                {
                    cr2 = lockedVal;
                    keyState2 = 0;
                }
                return;
            }

            // Force Write (CR.FW) seals an incomplete 256-bit write buffer immediately
            if((value & CrFwBit) != 0U)
            {
                SealActiveFlashWord(isBank1);
            }

            uint nextCr = value & ~(CrStartBit | CrFwBit);
            if(isBank1)
            {
                cr1 = nextCr;
            }
            else
            {
                cr2 = nextCr;
            }

            if((value & CrStartBit) != 0U && (value & CrSerBit) != 0U)
            {
                uint snb = (value >> CrSnbShift) & 0xFU;
                HandleSectorErase(isBank1, snb);
            }
        }

        private void SealActiveFlashWord(bool isBank1)
        {
            int activeFw = isBank1 ? activeFwBank1 : activeFwBank2;
            if(activeFw >= 0 && activeFw < totalFlashWords)
            {
                if(flashWordStrobeMask[activeFw] != 0)
                {
                    flashWordWritten[activeFw] = true;
                    flashWordStrobeMask[activeFw] = 0xFF;
                }
            }
            if(isBank1)
            {
                activeFwBank1 = -1;
            }
            else
            {
                activeFwBank2 = -1;
            }
        }

        private void HandleSectorErase(bool isBank1, uint snb)
        {
            if(isBank1)
            {
                if(snb >= SectorsPerBank)
                {
                    sr1 |= SrPgsErrBit;
                    return;
                }
                if(((committedWpsn1r >> (int)snb) & 1U) == 0U)
                {
                    BlockedOperations++;
                    sr1 |= SrWrpErrBit;
                    this.Log(LogLevel.Warning, "WPSN1R blocked sector erase on Bank 1 Sector {0}", snb);
                    return;
                }
                long secOffset = (long)snb * SectorSizeBytes;
                EraseSectorRange(secOffset);
                sr1 |= SrEopBit;
            }
            else
            {
                long maxBank2Sectors = (flash.Size - BankSizeBytes) / SectorSizeBytes;
                if(snb >= (uint)maxBank2Sectors)
                {
                    sr2 |= SrPgsErrBit;
                    return;
                }
                if(snb < SectorsPerBank && (((committedWpsn2r >> (int)snb) & 1U) == 0U))
                {
                    BlockedOperations++;
                    sr2 |= SrWrpErrBit;
                    this.Log(LogLevel.Warning, "WPSN2R blocked sector erase on Bank 2 Sector {0}", snb);
                    return;
                }
                long secOffset = BankSizeBytes + ((long)snb * SectorSizeBytes);
                EraseSectorRange(secOffset);
                sr2 |= SrEopBit;
            }
        }

        private void EraseSectorRange(long secOffset)
        {
            flash.SetRange(secOffset, SectorSizeBytes, 0xFF);
            int fwStart = (int)(secOffset / FlashWordBytes);
            int fwCount = (int)(SectorSizeBytes / FlashWordBytes);
            for(int i = 0; i < fwCount; i++)
            {
                flashWordWritten[fwStart + i] = false;
                flashWordStrobeMask[fwStart + i] = 0x00;
            }
            MarkFlashMutated();
        }

        private void MarkFlashMutated()
        {
            // Track bootloader-phase Flash mutations prior to OS VTOR handoff
            if(lastVtor < OsPartitionMinVtor)
            {
                flashDirtySinceSync = true;
                dcacheCleanedSinceMutation = false;
            }
        }

        private bool IsSectorWriteProtectedForOffset(long offset, out bool isBank1)
        {
            isBank1 = offset < BankSizeBytes;
            if(isBank1)
            {
                int sec = (int)(offset / SectorSizeBytes);
                return ((committedWpsn1r >> sec) & 1U) == 0U;
            }
            if(offset < (2L * BankSizeBytes))
            {
                int sec = (int)((offset - BankSizeBytes) / SectorSizeBytes);
                return ((committedWpsn2r >> sec) & 1U) == 0U;
            }
            return false;
        }

        private void RecordDoubleWriteViolation(bool isBank1, int fwIdx, long offset, uint value)
        {
            if(isBank1)
            {
                sr1 |= SrIncErrBit | SrPgsErrBit;
                if(lastDoubleWriteFwBank1 != fwIdx)
                {
                    lastDoubleWriteFwBank1 = fwIdx;
                    FlashWordDoubleWriteCount++;
                    this.Log(
                        LogLevel.Warning,
                        "RM0433 256-bit ECC violation: 32-byte Flash-Word double-write rejected at 0x{0:X8} (fwIdx={1}, val=0x{2:X8}, count={3})",
                        FlashBaseAddr + (ulong)offset,
                        fwIdx,
                        value,
                        FlashWordDoubleWriteCount);
                }
            }
            else
            {
                sr2 |= SrIncErrBit | SrPgsErrBit;
                if(lastDoubleWriteFwBank2 != fwIdx)
                {
                    lastDoubleWriteFwBank2 = fwIdx;
                    FlashWordDoubleWriteCount++;
                    this.Log(
                        LogLevel.Warning,
                        "RM0433 256-bit ECC violation: 32-byte Flash-Word double-write rejected at 0x{0:X8} (fwIdx={1}, val=0x{2:X8}, count={3})",
                        FlashBaseAddr + (ulong)offset,
                        fwIdx,
                        value,
                        FlashWordDoubleWriteCount);
                }
            }
        }

        private uint FilterWriteDoubleWord(uint value, long offset)
        {
            uint existing = flash.ReadDoubleWord(offset);
            if(offset < 0L || offset + 4L > flash.Size)
            {
                return existing;
            }

            bool isBank1;
            bool wrpProtected = IsSectorWriteProtectedForOffset(offset, out isBank1);
            uint cr = isBank1 ? cr1 : cr2;

            if((offset & 0x3L) != 0L)
            {
                if(isBank1) sr1 |= SrStrbErrBit | SrPgsErrBit;
                else sr2 |= SrStrbErrBit | SrPgsErrBit;
                return existing;
            }

            if(((cr & CrLockBit) != 0U) || ((cr & CrPgBit) == 0U))
            {
                if(isBank1) sr1 |= SrPgsErrBit;
                else sr2 |= SrPgsErrBit;
                return existing;
            }

            if(wrpProtected)
            {
                BlockedOperations++;
                if(isBank1) sr1 |= SrWrpErrBit;
                else sr2 |= SrWrpErrBit;
                this.Log(LogLevel.Warning, "WPSN blocked flash program at +0x{0:X6}", offset);
                return existing;
            }

            int fwIdx = (int)(offset / FlashWordBytes);
            int wordIdx = (int)((offset >> 2) & 0x7L);
            byte wordBit = (byte)(1 << wordIdx);

            int prevActiveFw = isBank1 ? activeFwBank1 : activeFwBank2;
            if(prevActiveFw >= 0 && prevActiveFw != fwIdx)
            {
                SealActiveFlashWord(isBank1);
                if(isBank1) lastDoubleWriteFwBank1 = -1;
                else lastDoubleWriteFwBank2 = -1;
            }

            // RM0433 Section 4.3.9: 266-bit SECDED ECC Write-Once Enforcer.
            // Any second write to a 32-byte Flash-Word without an intervening 128 KB Sector Erase
            // (even writing 0xFFFFFFFF!) corrupts the 10-bit ECC syndrome and raises INCERR/PGSERR.
            if(flashWordWritten[fwIdx] || ((flashWordStrobeMask[fwIdx] & wordBit) != 0))
            {
                RecordDoubleWriteViolation(isBank1, fwIdx, offset, value);
                return existing;
            }

            if(isBank1)
            {
                activeFwBank1 = fwIdx;
                lastDoubleWriteFwBank1 = -1;
            }
            else
            {
                activeFwBank2 = fwIdx;
                lastDoubleWriteFwBank2 = -1;
            }

            flashWordStrobeMask[fwIdx] |= wordBit;
            if(flashWordStrobeMask[fwIdx] == 0xFF)
            {
                flashWordWritten[fwIdx] = true;
                if(isBank1)
                {
                    activeFwBank1 = -1;
                    sr1 |= SrEopBit;
                }
                else
                {
                    activeFwBank2 = -1;
                    sr2 |= SrEopBit;
                }
            }

            MarkFlashMutated();
            return existing & value;
        }

        private ushort FilterWriteWord(ushort value, long offset)
        {
            ushort existing = flash.ReadWord(offset);
            if(offset < 0L || offset >= flash.Size)
            {
                return existing;
            }
            bool isBank1 = offset < BankSizeBytes;
            int fwIdx = (int)(offset / FlashWordBytes);
            if(flashWordWritten[fwIdx])
            {
                RecordDoubleWriteViolation(isBank1, fwIdx, offset, value);
            }
            else if(isBank1)
            {
                sr1 |= SrStrbErrBit | SrPgsErrBit;
            }
            else
            {
                sr2 |= SrStrbErrBit | SrPgsErrBit;
            }
            return existing;
        }

        private byte FilterWriteByte(byte value, long offset)
        {
            byte existing = flash.ReadByte(offset);
            if(offset < 0L || offset >= flash.Size)
            {
                return existing;
            }
            bool isBank1 = offset < BankSizeBytes;
            int fwIdx = (int)(offset / FlashWordBytes);
            if(flashWordWritten[fwIdx])
            {
                RecordDoubleWriteViolation(isBank1, fwIdx, offset, value);
            }
            else if(isBank1)
            {
                sr1 |= SrStrbErrBit | SrPgsErrBit;
            }
            else
            {
                sr2 |= SrStrbErrBit | SrPgsErrBit;
            }
            return existing;
        }

        private const ulong FlashBaseAddr = 0x08000000UL;
        private const ulong PageSizeBytes = 0x1000UL;
        private const long BankSizeBytes = 0x100000L;
        private const long SectorSizeBytes = 0x20000L;
        private const long FlashWordBytes = 32L;
        private const uint SectorsPerBank = 8U;

        private const uint FlashKey1 = 0x45670123U;
        private const uint FlashKey2 = 0xCDEF89ABU;
        private const uint OptKey1 = 0x08192A3BU;
        private const uint OptKey2 = 0x4C5D6E7FU;

        private const uint DefaultAcr = 0x00000037U;
        private const uint DefaultOptsr = 0x0406AAF0U;
        private const uint DefaultWpsn = 0x000000FFU;
        private const uint WpsnMask = 0x000000FFU;

        private const uint CrLockBit = 1U << 0;
        private const uint CrPgBit = 1U << 1;
        private const uint CrSerBit = 1U << 2;
        private const uint CrFwBit = 1U << 6;
        private const uint CrStartBit = 1U << 7;
        private const int CrSnbShift = 8;

        private const uint SrEopBit = 1U << 16;
        private const uint SrWrpErrBit = 1U << 17;
        private const uint SrPgsErrBit = 1U << 18;
        private const uint SrStrbErrBit = 1U << 19;
        private const uint SrIncErrBit = 1U << 21;
        private const uint CcrClearMask = 0x07EF0000U;

        private const uint OptLockBit = 1U << 0;
        private const uint OptStartBit = 1U << 1;
        private const uint OptsrOptBusyBit = 1U << 0;
        private const uint OptsrSwapBankOptBit = 1U << 31;

        // Cortex-M7 SCB Cache & VTOR Registers (offsets relative to NVIC @ 0xE000E000)
        private const long ScbVtorOffset = 0xD08L;
        private const long ScbCcrOffset = 0xD14L;
        private const long ScbCcsidrOffset = 0xD80L;
        private const long ScbCsselrOffset = 0xD84L;
        private const long ScbIcialluOffset = 0xF50L;
        private const long ScbDciswOffset = 0xF64L;
        private const long ScbDccimvacOffset = 0xF70L;
        private const long ScbDcciswOffset = 0xF74L;

        private const uint OsPartitionMinVtor = 0x08060000U;
        private const uint ScbCcrDcBit = 1U << 16;
        private const uint ScbCcrIcBit = 1U << 17;
        private const uint ScbCcsidrValue = 0x0003E019U; // 32 sets (sets=31), 4 ways (ways=3), 32B line
        private const uint FinalSetWayValue = (3U << 30) | (31U << 5);

        private readonly IMachine machine;
        private readonly MappedMemory flash;
        private readonly Stm32H753OtpUid otp;
        private readonly NVIC nvic;
        private readonly int totalFlashWords;
        private readonly bool[] flashWordWritten;
        private readonly byte[] flashWordStrobeMask;

        private bool hooksInstalled;
        private int keyState1;
        private int keyState2;
        private int optKeyState;
        private int activeFwBank1 = -1;
        private int activeFwBank2 = -1;
        private int lastDoubleWriteFwBank1 = -1;
        private int lastDoubleWriteFwBank2 = -1;

        private uint acr = DefaultAcr;
        private uint cr1 = CrLockBit;
        private uint sr1;
        private uint cr2 = CrLockBit;
        private uint sr2;
        private uint optcr;
        private uint optsrPrg;
        private uint committedOptsr;
        private uint wpsnPrg1r;
        private uint committedWpsn1r;
        private uint wpsnPrg2r;
        private uint committedWpsn2r;

        private uint scbCcrCacheBits;
        private uint scbCsselr;
        private uint lastVtor = 0x08000000U;
        private bool flashDirtySinceSync;
        private bool dcacheCleanedSinceMutation;
    }
}
