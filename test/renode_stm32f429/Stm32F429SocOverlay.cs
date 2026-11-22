//
// STMicroelectronics STM32F429ZI SoC Hardware Overlay for Headless Renode 1.17.0 E2E Testing
//
// Models RM0090 hardware peripherals with cycle/register-exact fidelity:
//   - BootAlias  (0x00000000): 1 MB boot alias window controlled by SYSCFG_MEMRMP.UFB_MODE / BFB2
//   - OtpUid     (0x1FFF7800): 512B OTP (16x32B, 1->0), 16B OTP lock bytes, 96-bit factory UID
//   - RtcBkp     (0x40002800): 20x32-bit backup registers (BKP0R..BKP19R), gated by PWR_CR.DBP
//   - Iwdg       (0x40003000): 32 kHz LSI Independent Watchdog latching RCC_CSR.IWDGRSTF
//   - Pwr        (0x40007000): Power control register (PWR_CR.DBP backup domain write enable)
//   - Syscfg     (0x40013800): SYSCFG_MEMRMP (UFB_MODE latched from FLASH_OPTCR.BFB2 on reset)
//   - Rcc        (0x40023800): Clock enables & persistent RCC_CSR reset flags (POR/PIN/SFT/IWDG/RMVF)
//   - FlashCtrl  (0x40023C00): 2 MB dual-bank asymmetric flash (24 sectors: 4x16K + 1x64K + 7x128K
//                              per bank), KEYR/OPTKEYR, BFB2, and hardware nWRP write/erase protection
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
    public class Stm32F429Rcc : IDoubleWordPeripheral, IKnownSize, IGPIOReceiver
    {
        public Stm32F429Rcc(IMachine machine)
        {
            this.machine = machine;
            csr = CsrPorRstfBit | CsrPinRstfBit | CsrLsiRdyBit;
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
            case 0x00: // CR (HSIRDY | HSION)
                return cr;
            case 0x04: // PLLCFGR
                return pllcfgr;
            case 0x08: // CFGR
                return cfgr;
            case 0x30: // AHB1ENR
                return ahb1enr;
            case 0x34: // AHB2ENR
                return ahb2enr;
            case 0x40: // APB1ENR
                return apb1enr;
            case 0x44: // APB2ENR
                return apb2enr;
            case 0x74: // CSR
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
                cr = value | 0x00000002U; // Keep HSIRDY asserted
                break;
            case 0x04:
                pllcfgr = value;
                break;
            case 0x08:
                cfgr = value;
                break;
            case 0x30:
                ahb1enr = value;
                break;
            case 0x34:
                ahb2enr = value;
                break;
            case 0x40:
                apb1enr = value;
                break;
            case 0x44:
                apb2enr = value;
                break;
            case 0x74:
                if((value & CsrRmvfBit) != 0U)
                {
                    csr &= ~CsrResetFlagsMask;
                }
                csr = (csr & CsrResetFlagsMask) | (value & 0x00FFFFFFU & ~CsrRmvfBit) | CsrLsiRdyBit;
                break;
            }
        }

        public void Reset()
        {
            cr = 0x00000083U;
            pllcfgr = 0x24003010U;
            cfgr = 0U;
            ahb1enr = 0x00100000U;
            ahb2enr = 0U;
            apb1enr = 0U;
            apb2enr = 0U;
            // RCC_CSR reset cause flags persist across warm resets until cleared via RMVF.
        }

        private const uint CsrLsiRdyBit = 1U << 1;
        private const uint CsrRmvfBit = 1U << 24;
        private const uint CsrPinRstfBit = 1U << 26;
        private const uint CsrPorRstfBit = 1U << 27;
        private const uint CsrSftRstfBit = 1U << 28;
        private const uint CsrIwdgRstfBit = 1U << 29;
        private const uint CsrResetFlagsMask = 0xFE000000U;

        private readonly IMachine machine;
        private uint cr = 0x00000083U;
        private uint pllcfgr = 0x24003010U;
        private uint cfgr;
        private uint ahb1enr = 0x00100000U;
        private uint ahb2enr;
        private uint apb1enr;
        private uint apb2enr;
        private uint csr;
    }

    public class Stm32F429Pwr : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        public bool IsBackupWriteEnabled => (cr & PwrCrDbpBit) != 0U;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00:
                return cr;
            case 0x04:
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
                cr = value;
                break;
            case 0x04:
                csr = value;
                break;
            }
        }

        public void Reset()
        {
            cr = 0x0000C000U; // DBP = 0 on reset per RM0090
            csr = 0U;
        }

        private const uint PwrCrDbpBit = 1U << 8;

        private uint cr = 0x0000C000U;
        private uint csr;
    }

    public class Stm32F429RtcBkp : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F429RtcBkp(Stm32F429Pwr pwr = null)
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
                    this.Log(LogLevel.Warning, "Blocked RTC_BKP{0}R write while PWR_CR.DBP=0", (offset - BkpStartOffset) >> 2);
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
        private const long BkpEndOffset = 0xA0L;

        private readonly Stm32F429Pwr pwr;
        private readonly uint[] bkp = new uint[20];
    }

    public class Stm32F429Syscfg : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        public bool IsBank2MappedAtZero => (memRmp & UfbModeBit) != 0U;

        public uint MemRmp => memRmp;

        internal void LatchBootBank(bool bank2Active)
        {
            latchedBank2 = bank2Active;
            if(bank2Active)
            {
                memRmp |= UfbModeBit;
            }
            else
            {
                memRmp &= ~UfbModeBit;
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
            memRmp = latchedBank2 ? UfbModeBit : 0U;
        }

        private const uint UfbModeBit = 1U << 8;

        private uint memRmp;
        private bool latchedBank2;
    }

    public class Stm32F429BootAlias : IDoubleWordPeripheral, IWordPeripheral, IBytePeripheral, IKnownSize
    {
        public Stm32F429BootAlias(MappedMemory flash, Stm32F429Syscfg syscfg = null)
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

        private const long BankSizeBytes = 0x100000L;

        private readonly MappedMemory flash;
        private readonly Stm32F429Syscfg syscfg;
    }

    public class Stm32F429Iwdg : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F429Iwdg(IMachine machine, Stm32F429Rcc rcc = null)
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
                return 0U; // PVU=0, RVU=0
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

        private readonly Stm32F429Rcc rcc;
        private readonly LimitTimer timer;
        private bool unlocked;
        private bool running;
        private uint pr;
        private uint rlr = 0xFFFU;
    }

    public class Stm32F429Rng : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F429Rng()
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
                // SplitMix64 mixing step
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

    public class Stm32F429OtpUid : IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F429OtpUid()
        {
            ResetToDefaultErased();
        }

        public long Size => 0x400;

        internal Stm32F429FlashController FlashController { get; set; }

        public void ResetToDefaultErased()
        {
            for(int i = 0; i < OtpTotalSavedBytes; i++)
            {
                otpBytes[i] = 0xFF;
            }
            byte[] defaultUid = { 0x32, 0x04, 0x29, 0x00, 0x48, 0x33, 0x54, 0x4D, 0xAA, 0x55, 0x11, 0x22 };
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
            if(offset < 0 || offset >= UidOffset)
            {
                // 96-bit factory UID at +0x210..+0x21B and unmapped bytes are read-only.
                return;
            }
            if(FlashController == null || !FlashController.IsPgEnabledAndUnlocked)
            {
                FlashController?.RaisePgsErr();
                return;
            }

            if(offset < OtpLockOffset)
            {
                int block = (int)(offset / OtpBlockBytes);
                byte lockByte = otpBytes[OtpLockOffset + block];
                if(lockByte == 0x00)
                {
                    FlashController.RaiseWrpErr();
                    return;
                }
                otpBytes[offset] &= value;
                FlashController.RaiseEop();
                return;
            }

            // OTP Lock bytes (+0x200..+0x20F): 1->0 irreversible lock
            otpBytes[offset] &= value;
            FlashController.RaiseEop();
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
        private const int UidOffset = 0x210;
        private const int OtpTotalSavedBytes = 0x220;

        private readonly byte[] otpBytes = new byte[OtpTotalSavedBytes];
    }

    public class Stm32F429FlashController : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F429FlashController(
            IMachine machine,
            MappedMemory flash,
            Stm32F429OtpUid otp = null,
            Stm32F429Syscfg syscfg = null)
        {
            this.machine = machine;
            this.flash = flash;
            this.otp = otp;
            this.syscfg = syscfg;
            if(this.otp != null)
            {
                this.otp.FlashController = this;
            }

            committedOptcr = DefaultOptcr & ~OptLockBit;
            committedOptcr1 = DefaultOptcr1;
            optcr = DefaultOptcr;
            optcr1 = DefaultOptcr1;
        }

        public long Size => 0x400;

        public uint BlockedOperations { get; private set; }

        public uint CommittedOptcr
        {
            get => committedOptcr | OptLockBit;
            set
            {
                committedOptcr = value & ~OptLockBit;
                optcr = committedOptcr | OptLockBit;
                syscfg?.LatchBootBank((committedOptcr & OptBfb2Bit) != 0U);
            }
        }

        public uint CommittedOptcr1
        {
            get => committedOptcr1;
            set
            {
                committedOptcr1 = value & 0x0FFF0000U;
                optcr1 = committedOptcr1;
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

        internal void RaiseEop()
        {
            sr |= SrEopBit;
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
            for(ulong page = 0UL; page < flashLen; page += PageSizeBytes)
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
            case 0x0C: // SR
                return sr;
            case 0x10: // CR
                return cr;
            case 0x14: // OPTCR
                return optcr;
            case 0x18: // OPTCR1
                return optcr1;
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

            case 0x04: // KEYR
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

            case 0x08: // OPTKEYR
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

            case 0x0C: // SR (write-1-to-clear status & error flags)
                sr &= ~(value & SrClearMask);
                break;

            case 0x10: // CR
                if((cr & CrLockBit) != 0U)
                {
                    return;
                }
                if((value & CrLockBit) != 0U)
                {
                    cr = (value & ~CrStrtBit) | CrLockBit;
                    keyState = 0;
                    return;
                }
                cr = value & ~CrStrtBit;
                if((value & CrStrtBit) != 0U && (value & CrSerBit) != 0U)
                {
                    uint snb = (value >> CrSnbShift) & 0x1FU;
                    HandleSectorErase(snb);
                }
                break;

            case 0x14: // OPTCR
                if((optcr & OptLockBit) != 0U)
                {
                    return;
                }
                bool lockAfter = (value & OptLockBit) != 0U;
                bool startOpt = (value & OptStrtBit) != 0U;
                optcr = value & ~OptStrtBit;
                if(startOpt)
                {
                    committedOptcr = optcr & ~OptLockBit;
                    committedOptcr1 = optcr1;
                    syscfg?.LatchBootBank((committedOptcr & OptBfb2Bit) != 0U);
                    sr |= SrEopBit;
                }
                if(lockAfter)
                {
                    optcr |= OptLockBit;
                    optKeyState = 0;
                }
                break;

            case 0x18: // OPTCR1
                if((optcr & OptLockBit) != 0U)
                {
                    return;
                }
                optcr1 = value & 0x0FFF0000U;
                break;
            }
        }

        public void Reset()
        {
            acr = 0U;
            sr = 0U;
            cr = CrLockBit;
            keyState = 0;
            optKeyState = 0;
            optcr = committedOptcr | OptLockBit;
            optcr1 = committedOptcr1;
            syscfg?.LatchBootBank((committedOptcr & OptBfb2Bit) != 0U);
            if(hooksInstalled)
            {
                ApplyPageAccessViaIo();
            }
        }

        private void HandleSectorErase(uint snb)
        {
            uint bank;
            uint secInBank;
            if(snb <= 11U)
            {
                bank = 0U;
                secInBank = snb;
            }
            else if(snb >= 0x10U && snb <= 0x1BU)
            {
                bank = 1U;
                secInBank = snb - 0x10U;
            }
            else
            {
                sr |= SrPgsErrBit;
                return;
            }

            if(IsSectorWriteProtected(bank, secInBank))
            {
                BlockedOperations++;
                sr |= SrWrpErrBit;
                this.Log(LogLevel.Warning, "nWRP blocked sector erase on bank {0} sector {1} (SNB=0x{2:X2})", bank, secInBank, snb);
                return;
            }

            GetSectorGeometry(bank, secInBank, out long secOffset, out long secSize);
            flash.SetRange(secOffset, secSize, 0xFF);
            sr |= SrEopBit;
        }

        private bool IsSectorWriteProtected(uint bank, uint secInBank)
        {
            uint reg = (bank == 0U) ? committedOptcr : committedOptcr1;
            uint nwrpBit = (reg >> (int)(16U + secInBank)) & 1U;
            // RM0090 active-low nWRP: 0 = write protection active, 1 = writable.
            return nwrpBit == 0U;
        }

        private static void GetSectorGeometry(uint bank, uint secInBank, out long offset, out long size)
        {
            long bankBase = (long)bank * BankSizeBytes;
            if(secInBank < 4U)
            {
                offset = bankBase + ((long)secInBank * 0x4000L);
                size = 0x4000L;
            }
            else if(secInBank == 4U)
            {
                offset = bankBase + 0x10000L;
                size = 0x10000L;
            }
            else
            {
                offset = bankBase + 0x20000L + ((long)(secInBank - 5U) * 0x20000L);
                size = 0x20000L;
            }
        }

        private static void LookupSectorForOffset(long offset, out uint bank, out uint secInBank)
        {
            bank = (offset >= BankSizeBytes) ? 1U : 0U;
            long inBank = offset - ((long)bank * BankSizeBytes);
            if(inBank < 0x10000L)
            {
                secInBank = (uint)(inBank / 0x4000L);
            }
            else if(inBank < 0x20000L)
            {
                secInBank = 4U;
            }
            else
            {
                secInBank = 5U + (uint)((inBank - 0x20000L) / 0x20000L);
            }
        }

        private bool CheckFlashProgramAllowed(long offset)
        {
            if(offset < 0L || offset >= flash.Size)
            {
                return false;
            }
            if(!IsPgEnabledAndUnlocked)
            {
                sr |= SrPgsErrBit;
                return false;
            }
            LookupSectorForOffset(offset, out uint bank, out uint secInBank);
            if(IsSectorWriteProtected(bank, secInBank))
            {
                BlockedOperations++;
                sr |= SrWrpErrBit;
                this.Log(LogLevel.Warning, "nWRP blocked flash program at +0x{0:X6} (bank {1}, sec {2})", offset, bank, secInBank);
                return false;
            }
            sr |= SrEopBit;
            return true;
        }

        private uint FilterWriteDoubleWord(uint value, long offset)
        {
            uint existing = flash.ReadDoubleWord(offset);
            if(!CheckFlashProgramAllowed(offset))
            {
                return existing;
            }
            return existing & value;
        }

        private ushort FilterWriteWord(ushort value, long offset)
        {
            ushort existing = flash.ReadWord(offset);
            if(!CheckFlashProgramAllowed(offset))
            {
                return existing;
            }
            return (ushort)(existing & value);
        }

        private byte FilterWriteByte(byte value, long offset)
        {
            byte existing = flash.ReadByte(offset);
            if(!CheckFlashProgramAllowed(offset))
            {
                return existing;
            }
            return (byte)(existing & value);
        }

        private const ulong FlashBaseAddr = 0x08000000UL;
        private const ulong PageSizeBytes = 0x1000UL;
        private const long BankSizeBytes = 0x100000L;

        private const uint FlashKey1 = 0x45670123U;
        private const uint FlashKey2 = 0xCDEF89ABU;
        private const uint OptKey1 = 0x08192A3BU;
        private const uint OptKey2 = 0x4C5D6E7FU;

        private const uint SrEopBit = 1U << 0;
        private const uint SrWrpErrBit = 1U << 4;
        private const uint SrPgsErrBit = 1U << 7;
        private const uint SrClearMask = 0x000001F3U;

        private const uint CrPgBit = 1U << 0;
        private const uint CrSerBit = 1U << 1;
        private const int CrSnbShift = 3;
        private const uint CrStrtBit = 1U << 16;
        private const uint CrLockBit = 1U << 31;

        private const uint OptLockBit = 1U << 0;
        private const uint OptStrtBit = 1U << 1;
        private const uint OptBfb2Bit = 1U << 4;
        private const uint DefaultOptcr = 0x0FFFAAEDU;
        private const uint DefaultOptcr1 = 0x0FFF0000U;

        private readonly IMachine machine;
        private readonly MappedMemory flash;
        private readonly Stm32F429OtpUid otp;
        private readonly Stm32F429Syscfg syscfg;

        private bool hooksInstalled;
        private int keyState;
        private int optKeyState;
        private uint acr;
        private uint sr;
        private uint cr = CrLockBit;
        private uint optcr;
        private uint optcr1;
        private uint committedOptcr;
        private uint committedOptcr1;
    }
}
