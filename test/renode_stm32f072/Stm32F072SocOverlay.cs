//
// STMicroelectronics STM32F072xB (ARM Cortex-M0 ARMv6-M, No VTOR) SoC Hardware Overlay
// for Headless Renode 1.17.0 End-to-End Testing
//
// Models RM0091 hardware peripherals with register-exact fidelity:
//   - Syscfg      (0x40010000): SYSCFG_CFGR1.MEM_MODE[1:0] (0x0 = Main Flash, 0x3 = SRAM at 0x00000000)
//                               + SCB->VTOR (0xE000ED08) illegal-write trap proving zero VTOR writes!
//   - BootAlias   (0x00000000): 256 KB boot/vector alias window controlled by SYSCFG_CFGR1.MEM_MODE
//   - OtpOptBlock (0x1FFFF000): Protected OTP keystore (+0x000), OTP slot locks (+0x200),
//                               96-bit factory UID (+0x7AC), and RM0091 Option Bytes OB.WRP0..3 (+0x800)
//   - RtcBkp      (0x40002800): 5x32-bit backup registers (BKP0R..BKP4R at +0x50), gated by PWR_CR.DBP
//   - Iwdg        (0x40003000): 40 kHz LSI Independent Watchdog latching RCC_CSR.IWDGRSTF
//   - Pwr         (0x40007000): Power control register (PWR_CR.DBP backup domain write enable)
//   - AdcEntropy  (0x40012400): RM0091 ADC1 + internal temperature/VREFINT thermal noise source
//   - Rcc         (0x40021000): Clock enables, HSI14 (RCC_CR2), & persistent RCC_CSR reset flags
//   - FlashCtrl   (0x40022000): RM0091 FPEC (2 KB homogeneous pages, 16-bit halfword PG, OB.WRP0..3)
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
    public class Stm32F072Syscfg : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F072Syscfg(IMachine machine)
        {
            this.machine = machine;
        }

        public long Size => 0x400;

        public uint Cfgr1 => cfgr1;

        public bool IsSramMappedAtZero => (cfgr1 & MemModeMask) == MemModeSram;

        public uint VtorWriteAttempts { get; private set; }

        public IBusPeripheral Nvic { get; set; }

        public void InstallVtorTrap()
        {
            if(vtorTrapInstalled || Nvic == null)
            {
                return;
            }
            var sysbus = (SystemBus)machine.SystemBus;
            sysbus.SetHookBeforePeripheralWrite<uint>(Nvic, FilterNvicWrite);
            vtorTrapInstalled = true;
        }

        internal void PrepareSystemReset()
        {
            // RM0091 Section 9.1.1: SYSCFG_CFGR1 resets to 0x00000000 (Main Flash at 0x00000000)
            // before Cortex-M0 fetches initial MSP/PC from 0x00000000 / 0x00000004.
            cfgr1 = 0U;
        }

        public uint ReadDoubleWord(long offset)
        {
            if(offset == 0x00L)
            {
                return cfgr1;
            }
            return 0U;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(offset == 0x00L)
            {
                cfgr1 = value & 0x3FFFFFFFU;
            }
        }

        public void Reset()
        {
            cfgr1 = 0U;
        }

        private uint FilterNvicWrite(uint value, long offset)
        {
            // SCB->VTOR (0xE000ED08 == NVIC base 0xE000E000 + 0xD08) does NOT exist on ARMv6-M Cortex-M0!
            if(offset == ScbVtorOffsetInNvic)
            {
                VtorWriteAttempts++;
                this.Log(LogLevel.Error, "[VTOR_TRAP] ILLEGAL Cortex-M0 write to SCB->VTOR (0xE000ED08) = 0x{0:X8}!", value);
                return 0U;
            }
            return value;
        }

        private const long ScbVtorOffsetInNvic = 0xD08L;
        private const uint MemModeMask = 0x3U;
        private const uint MemModeSram = 0x3U;

        private readonly IMachine machine;
        private bool vtorTrapInstalled;
        private uint cfgr1;
    }

    public class Stm32F072BootAlias : IDoubleWordPeripheral, IWordPeripheral, IBytePeripheral, IKnownSize
    {
        public Stm32F072BootAlias(MappedMemory flash, MappedMemory sram, Stm32F072Syscfg syscfg = null)
        {
            this.flash = flash;
            this.sram = sram;
            this.syscfg = syscfg;
        }

        public long Size => FlashSizeBytes;

        private bool MapToSram => syscfg != null && syscfg.IsSramMappedAtZero;

        public uint ReadDoubleWord(long offset)
        {
            if(MapToSram)
            {
                return sram.ReadDoubleWord(offset & (SramSizeBytes - 1L));
            }
            return flash.ReadDoubleWord(offset & (FlashSizeBytes - 1L));
        }

        public ushort ReadWord(long offset)
        {
            if(MapToSram)
            {
                return sram.ReadWord(offset & (SramSizeBytes - 1L));
            }
            return flash.ReadWord(offset & (FlashSizeBytes - 1L));
        }

        public byte ReadByte(long offset)
        {
            if(MapToSram)
            {
                return sram.ReadByte(offset & (SramSizeBytes - 1L));
            }
            return flash.ReadByte(offset & (FlashSizeBytes - 1L));
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(MapToSram)
            {
                sram.WriteDoubleWord(offset & (SramSizeBytes - 1L), value);
            }
        }

        public void WriteWord(long offset, ushort value)
        {
            if(MapToSram)
            {
                sram.WriteWord(offset & (SramSizeBytes - 1L), value);
            }
        }

        public void WriteByte(long offset, byte value)
        {
            if(MapToSram)
            {
                sram.WriteByte(offset & (SramSizeBytes - 1L), value);
            }
        }

        public void Reset()
        {
        }

        private const long FlashSizeBytes = 0x40000L; // 256 KB
        private const long SramSizeBytes = 0x4000L;   // 16 KB

        private readonly MappedMemory flash;
        private readonly MappedMemory sram;
        private readonly Stm32F072Syscfg syscfg;
    }

    public class Stm32F072Rcc : IDoubleWordPeripheral, IKnownSize, IGPIOReceiver
    {
        public Stm32F072Rcc(IMachine machine, Stm32F072Syscfg syscfg = null)
        {
            this.machine = machine;
            this.syscfg = syscfg;
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
                syscfg?.PrepareSystemReset();
                this.Log(LogLevel.Info, "SYSRESETREQ latched RCC_CSR=0x{0:X8}; requesting warm reset.", csr);
                machine.RequestReset();
            }
        }

        public void LatchWatchdogReset()
        {
            csr |= CsrIwdgRstfBit;
            syscfg?.PrepareSystemReset();
            this.Log(LogLevel.Info, "IWDG timeout latched RCC_CSR=0x{0:X8}; requesting warm reset.", csr);
            machine.RequestReset();
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // CR
                return cr;
            case 0x04: // CFGR
                return cfgr;
            case 0x18: // APB2ENR
                return apb2enr;
            case 0x1C: // APB1ENR
                return apb1enr;
            case 0x24: // CSR
                return csr;
            case 0x34: // CR2 (HSI14)
                return cr2;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00: // CR
                cr = value | 0x00000002U; // Keep HSIRDY asserted
                break;
            case 0x04: // CFGR
                cfgr = value;
                break;
            case 0x18: // APB2ENR
                apb2enr = value;
                break;
            case 0x1C: // APB1ENR
                apb1enr = value;
                break;
            case 0x24: // CSR
                if((value & CsrRmvfBit) != 0U)
                {
                    csr &= ~CsrResetFlagsMask;
                }
                csr = (csr & CsrResetFlagsMask) | (value & ~CsrResetFlagsMask & ~CsrRmvfBit) | CsrLsiRdyBit;
                break;
            case 0x34: // CR2
                if((value & Cr2Hsi14OnBit) != 0U)
                {
                    cr2 = value | Cr2Hsi14RdyBit;
                }
                else
                {
                    cr2 = value & ~Cr2Hsi14RdyBit;
                }
                break;
            }
        }

        public void Reset()
        {
            cr = 0x00000083U;
            cfgr = 0U;
            apb2enr = 0U;
            apb1enr = 0U;
            cr2 = 0x00000080U;
            // RCC_CSR reset cause flags persist across warm resets until cleared via RMVF.
        }

        private const uint Cr2Hsi14OnBit = 1U << 0;
        private const uint Cr2Hsi14RdyBit = 1U << 1;

        private const uint CsrLsiRdyBit = 1U << 1;
        private const uint CsrRmvfBit = 1U << 24;
        private const uint CsrPinRstfBit = 1U << 26;
        private const uint CsrPorRstfBit = 1U << 27;
        private const uint CsrSftRstfBit = 1U << 28;
        private const uint CsrIwdgRstfBit = 1U << 29;
        private const uint CsrResetFlagsMask = 0xFE800000U;

        private readonly IMachine machine;
        private readonly Stm32F072Syscfg syscfg;
        private uint cr = 0x00000083U;
        private uint cfgr;
        private uint apb2enr;
        private uint apb1enr;
        private uint cr2 = 0x00000080U;
        private uint csr;
    }

    public class Stm32F072Pwr : IDoubleWordPeripheral, IKnownSize
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
            cr = 0U; // DBP = 0 on reset per RM0091 Section 5.4.1
            csr = 0U;
        }

        private const uint PwrCrDbpBit = 1U << 8;

        private uint cr;
        private uint csr;
    }

    public class Stm32F072RtcBkp : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F072RtcBkp(Stm32F072Pwr pwr = null)
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
            // RM0091 Section 25.7.21: Backup registers BKP0R..BKP4R survive software and watchdog resets.
        }

        private const long BkpStartOffset = 0x50L;
        private const long BkpEndOffset = 0x64L; // 5 x 32-bit registers (BKP0R..BKP4R)

        private readonly Stm32F072Pwr pwr;
        private readonly uint[] bkp = new uint[5];
    }

    public class Stm32F072Iwdg : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F072Iwdg(IMachine machine, Stm32F072Rcc rcc = null)
        {
            this.rcc = rcc;
            timer = new LimitTimer(
                machine.ClockSource,
                40000UL,
                this,
                "stm32f0_iwdg_timer",
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
            case 0x04: // PR
                return pr;
            case 0x08: // RLR
                return rlr;
            case 0x0C: // SR (PVU=0, RVU=0, WVU=0)
                return 0U;
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

        private readonly Stm32F072Rcc rcc;
        private readonly LimitTimer timer;
        private bool unlocked;
        private bool running;
        private uint pr;
        private uint rlr = 0xFFFU;
    }

    public class Stm32F072AdcEntropy : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F072AdcEntropy()
        {
            byte[] seedBytes = Guid.NewGuid().ToByteArray();
            ulong s0 = BitConverter.ToUInt64(seedBytes, 0);
            ulong s1 = BitConverter.ToUInt64(seedBytes, 8);
            state = s0 ^ s1 ^ 0x9E3779B97F4A7C15UL;
            if(state == 0UL)
            {
                state = 0xF072CAFEBABE1234UL;
            }
        }

        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // ISR
                return isr;
            case 0x08: // CR
                return cr;
            case 0x0C: // CFGR1
                return cfgr1;
            case 0x14: // SMPR
                return smpr;
            case 0x28: // CHSELR
                return chselr;
            case 0x40: // DR
                isr &= ~AdcIsrEocBit;
                return dr;
            case 0x308: // CCR
                return ccr;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00: // ISR (write-1-to-clear flags)
                isr &= ~value;
                break;
            case 0x08: // CR
                if((value & AdcCrAddisBit) != 0U)
                {
                    cr &= ~(AdcCrAdenBit | AdcCrAddisBit | AdcCrAdstartBit);
                    isr &= ~(AdcIsrAdrdyBit | AdcIsrEocBit);
                    break;
                }
                if((value & AdcCrAdenBit) != 0U)
                {
                    cr |= AdcCrAdenBit;
                    isr |= AdcIsrAdrdyBit;
                }
                if(((cr & AdcCrAdenBit) != 0U) && ((value & AdcCrAdstartBit) != 0U))
                {
                    dr = DrawThermalNoiseSample();
                    isr |= AdcIsrEocBit;
                }
                break;
            case 0x0C: // CFGR1
                cfgr1 = value;
                break;
            case 0x14: // SMPR
                smpr = value;
                break;
            case 0x28: // CHSELR
                chselr = value;
                break;
            case 0x308: // CCR
                ccr = value;
                break;
            }
        }

        public void Reset()
        {
            isr = 0U;
            cr = 0U;
            cfgr1 = 0U;
            smpr = 0U;
            chselr = 0U;
            dr = 0U;
            ccr = 0U;
            lastSample = 0U;
        }

        private uint DrawThermalNoiseSample()
        {
            for(int i = 0; i < 8; i++)
            {
                state += 0x9E3779B97F4A7C15UL;
                ulong z = state;
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
                z ^= z >> 31;
                uint sample = (uint)(z & 0xFFFFUL);
                if(sample != 0U && sample != lastSample)
                {
                    lastSample = sample;
                    return sample;
                }
            }
            lastSample = (lastSample ^ 0x5A3CU) & 0xFFFFU;
            return lastSample;
        }

        private const uint AdcIsrAdrdyBit = 1U << 0;
        private const uint AdcIsrEocBit = 1U << 2;

        private const uint AdcCrAdenBit = 1U << 0;
        private const uint AdcCrAddisBit = 1U << 1;
        private const uint AdcCrAdstartBit = 1U << 2;

        private ulong state;
        private uint isr;
        private uint cr;
        private uint cfgr1;
        private uint smpr;
        private uint chselr;
        private uint dr;
        private uint ccr;
        private uint lastSample;
    }

    public class Stm32F072OtpOptBlock : IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F072OtpOptBlock()
        {
            ResetToDefaultErased();
        }

        public long Size => TotalBlockBytes;

        internal Stm32F072FlashController FlashController { get; set; }

        public void ResetToDefaultErased()
        {
            for(int i = 0; i < TotalBlockBytes; i++)
            {
                rawBytes[i] = 0xFF;
            }
            byte[] defaultUid = { 0x32, 0x00, 0x72, 0x00, 0x46, 0x30, 0x53, 0x54, 0xAA, 0x55, 0x07, 0x2B };
            Array.Copy(defaultUid, 0, rawBytes, UidOffset, defaultUid.Length);

            // Default RM0091 Section 4.1 factory Option Bytes at +0x800..+0x80F:
            // [0] RDP = 0xAA (~0x55), [1] USER = 0xFF (~0x00), [2..3] Data0..1 = 0xFF, [4..7] WRP0..3 = 0xFF
            WriteRawOptionHalfword(0, 0xAA);
            for(int i = 1; i < OptionHalfwordCount; i++)
            {
                WriteRawOptionHalfword(i, 0xFF);
            }
        }

        public void LoadBinary(string path)
        {
            ResetToDefaultErased();
            byte[] fileData = File.ReadAllBytes(path);
            int len = Math.Min(fileData.Length, TotalBlockBytes);
            Array.Copy(fileData, 0, rawBytes, 0, len);
            FlashController?.RefreshOptionBytes();
        }

        public void SaveBinary(string path)
        {
            byte[] outBytes = new byte[TotalBlockBytes];
            Array.Copy(rawBytes, 0, outBytes, 0, TotalBlockBytes);
            File.WriteAllBytes(path, outBytes);
        }

        internal void EraseOptionBytes()
        {
            for(int i = OptionBytesOffset; i < OptionBytesOffset + OptionBytesSize; i++)
            {
                rawBytes[i] = 0xFF;
            }
        }

        internal uint ComputeWrprRegister()
        {
            uint wrp0 = rawBytes[OptionBytesOffset + 8];
            uint wrp1 = rawBytes[OptionBytesOffset + 10];
            uint wrp2 = rawBytes[OptionBytesOffset + 12];
            uint wrp3 = rawBytes[OptionBytesOffset + 14];
            return wrp0 | (wrp1 << 8) | (wrp2 << 16) | (wrp3 << 24);
        }

        public byte ReadByte(long offset)
        {
            if(offset >= 0 && offset < TotalBlockBytes)
            {
                return rawBytes[offset];
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
            // RM0091 FPEC rejects 8-bit writes to OTP / Option Bytes
            FlashController?.RaisePgErr();
        }

        public void WriteWord(long offset, ushort value)
        {
            if((offset & 1L) != 0L || offset < 0L || offset + 2L > TotalBlockBytes)
            {
                FlashController?.RaisePgErr();
                return;
            }

            // Option Bytes window: 0x1FFFF800 .. 0x1FFFF80F
            if(offset >= OptionBytesOffset && offset < (OptionBytesOffset + OptionBytesSize))
            {
                if(FlashController == null || !FlashController.IsOptPgEnabledAndUnlocked)
                {
                    FlashController?.RaisePgErr();
                    return;
                }
                ushort curOpt = ReadWord(offset);
                if((value & (ushort)~curOpt) != 0)
                {
                    FlashController.RaisePgErr();
                    return;
                }
                ushort nextOpt = (ushort)(curOpt & value);
                rawBytes[offset] = (byte)(nextOpt & 0xFFU);
                rawBytes[offset + 1] = (byte)((nextOpt >> 8) & 0xFFU);
                FlashController.RefreshOptionBytes();
                FlashController.RaiseEop();
                return;
            }

            // Protected OTP payload & lock window: 0x1FFFF000 .. 0x1FFFF207
            if(offset < OtpEndOffset)
            {
                if(FlashController == null || !FlashController.IsPgEnabledAndUnlocked)
                {
                    FlashController?.RaisePgErr();
                    return;
                }

                // Pubkey slots 0..3 (+0x000..+0x07F) honor per-slot lock halfwords at +0x200..+0x207
                if(offset < (OtpPubkeySlots * OtpPubkeySlotBytes))
                {
                    int slot = (int)(offset / OtpPubkeySlotBytes);
                    ushort lockHw = ReadWord(OtpLockOffset + (slot * 2));
                    if(lockHw != 0xFFFFU)
                    {
                        FlashController.RaiseWrprtErr();
                        return;
                    }
                }

                ushort cur = ReadWord(offset);
                if((value & (ushort)~cur) != 0)
                {
                    FlashController.RaisePgErr();
                    return;
                }
                ushort next = (ushort)(cur & value);
                rawBytes[offset] = (byte)(next & 0xFFU);
                rawBytes[offset + 1] = (byte)((next >> 8) & 0xFFU);
                FlashController.RaiseEop();
                return;
            }

            // 96-bit factory UID (+0x7AC..+0x7B7) and reserved ROM bytes are strictly read-only
            FlashController?.RaiseWrprtErr();
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            WriteWord(offset, (ushort)(value & 0xFFFFU));
            WriteWord(offset + 2L, (ushort)((value >> 16) & 0xFFFFU));
        }

        public void Reset()
        {
            // Non-volatile OTP, lock halfwords, UID, and Option Bytes survive all resets.
        }

        private void WriteRawOptionHalfword(int index, byte lowByte)
        {
            int pos = OptionBytesOffset + (index * 2);
            rawBytes[pos] = lowByte;
            rawBytes[pos + 1] = (byte)(~lowByte);
        }

        private const int OtpPubkeySlots = 4;
        private const int OtpPubkeySlotBytes = 32;
        private const int OtpLockOffset = 0x200;
        private const int OtpEndOffset = 0x208;
        private const int UidOffset = 0x7AC;
        private const int OptionBytesOffset = 0x800;
        private const int OptionHalfwordCount = 8;
        private const int OptionBytesSize = OptionHalfwordCount * 2;
        private const int TotalBlockBytes = 0x1000;

        private readonly byte[] rawBytes = new byte[TotalBlockBytes];
    }

    public class Stm32F072FlashController : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32F072FlashController(
            IMachine machine,
            MappedMemory flash,
            Stm32F072OtpOptBlock otp = null)
        {
            this.machine = machine;
            this.flash = flash;
            this.otp = otp;
            if(this.otp != null)
            {
                this.otp.FlashController = this;
                wrpr = this.otp.ComputeWrprRegister();
            }
        }

        public long Size => 0x400;

        public uint BlockedOperations { get; private set; }

        public uint Wrpr => wrpr;

        internal bool IsPgEnabledAndUnlocked => ((cr & CrLockBit) == 0U) && ((cr & CrPgBit) != 0U);

        internal bool IsOptPgEnabledAndUnlocked =>
            ((cr & CrLockBit) == 0U) && ((cr & CrOptWreBit) != 0U) && ((cr & CrOptPgBit) != 0U);

        internal void RefreshOptionBytes()
        {
            if(otp != null)
            {
                wrpr = otp.ComputeWrprRegister();
            }
        }

        internal void RaiseWrprtErr()
        {
            BlockedOperations++;
            sr |= SrWrprtErrBit;
        }

        internal void RaisePgErr()
        {
            sr |= SrPgErrBit;
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
            for(ulong page = 0UL; page < flashLen; page += MmuPageBytes)
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
            case 0x14: // AR
                return ar;
            case 0x1C: // OBR (Level 0 RDP, OPTERR=0)
                return obr;
            case 0x20: // WRPR
                return wrpr;
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
                if(keyState == 0 && value == FpecKey1)
                {
                    keyState = 1;
                }
                else if(keyState == 1 && value == FpecKey2)
                {
                    cr &= ~CrLockBit;
                    keyState = 0;
                }
                else
                {
                    keyState = 0;
                }
                break;

            case 0x08: // OPTKEYR (RM0091 Section 3.5.3: same key pair unlocks CR.OPTWRE)
                if((cr & CrLockBit) != 0U)
                {
                    optKeyState = 0;
                    break;
                }
                if(optKeyState == 0 && value == FpecKey1)
                {
                    optKeyState = 1;
                }
                else if(optKeyState == 1 && value == FpecKey2)
                {
                    cr |= CrOptWreBit;
                    optKeyState = 0;
                }
                else
                {
                    optKeyState = 0;
                }
                break;

            case 0x0C: // SR (write-1-to-clear EOP, WRPRTERR, PGERR)
                sr &= ~(value & SrClearMask);
                break;

            case 0x10: // CR
                if((cr & CrLockBit) != 0U)
                {
                    return;
                }
                if((value & CrLockBit) != 0U)
                {
                    // Setting LOCK locks FPEC and clears OPTWRE
                    cr = CrLockBit;
                    keyState = 0;
                    optKeyState = 0;
                    return;
                }

                // Software cannot set OPTWRE directly via CR write; it can only preserve or clear it
                uint preservedOptWre = cr & CrOptWreBit;
                uint nextOptWre = preservedOptWre & (value & CrOptWreBit);
                cr = (value & ~(CrStrtBit | CrOptWreBit)) | nextOptWre;

                if((value & CrStrtBit) != 0U)
                {
                    if((cr & CrPerBit) != 0U)
                    {
                        HandlePageErase(ar);
                    }
                    else if(((cr & CrOptErBit) != 0U) && ((cr & CrOptWreBit) != 0U))
                    {
                        otp?.EraseOptionBytes();
                        RefreshOptionBytes();
                        sr |= SrEopBit;
                    }
                }
                break;

            case 0x14: // AR
                if((cr & CrLockBit) == 0U)
                {
                    ar = value;
                }
                break;
            }
        }

        public void Reset()
        {
            acr = 0x00000030U;
            sr = 0U;
            cr = CrLockBit;
            ar = 0U;
            obr = DefaultObr;
            keyState = 0;
            optKeyState = 0;
            RefreshOptionBytes();
            if(hooksInstalled)
            {
                ApplyPageAccessViaIo();
            }
        }

        private void HandlePageErase(uint targetAddr)
        {
            if(targetAddr < FlashBaseAddr || targetAddr >= (FlashBaseAddr + (ulong)flash.Size))
            {
                sr |= SrPgErrBit;
                return;
            }

            long pageOffset = (long)(targetAddr - (uint)FlashBaseAddr) & ~(FlashPageBytes - 1L);
            if(IsOffsetWriteProtected(pageOffset))
            {
                BlockedOperations++;
                sr |= SrWrprtErrBit;
                this.Log(LogLevel.Warning, "OB.WRP blocked 2 KB page erase at 0x{0:X8} (WRPR=0x{1:X8})", targetAddr, wrpr);
                return;
            }

            flash.SetRange(pageOffset, FlashPageBytes, 0xFF);
            sr |= SrEopBit;
        }

        private bool IsOffsetWriteProtected(long offset)
        {
            // RM0091 Section 3.3.3: Each WRPR bit protects two 2 KB pages (4 KB = 4096 B), active-low (0 = protected).
            int unit = (int)(offset / WrpUnitBytes);
            if(unit < 0)
            {
                return false;
            }
            if(unit > 31)
            {
                unit = 31;
            }
            return ((wrpr >> unit) & 1U) == 0U;
        }

        private bool CheckFlashHalfwordProgramAllowed(long offset, ushort value, ushort existing)
        {
            if(offset < 0L || (offset + 2L) > flash.Size || ((offset & 1L) != 0L))
            {
                sr |= SrPgErrBit;
                return false;
            }
            if(!IsPgEnabledAndUnlocked)
            {
                sr |= SrPgErrBit;
                return false;
            }
            if(IsOffsetWriteProtected(offset))
            {
                BlockedOperations++;
                sr |= SrWrprtErrBit;
                this.Log(LogLevel.Warning, "OB.WRP blocked halfword write at +0x{0:X5} (WRPR=0x{1:X8})", offset, wrpr);
                return false;
            }
            // RM0091 NOR flash rule: 0 -> 1 bit transitions without page erase trigger PGERR
            if((value & (ushort)~existing) != 0)
            {
                sr |= SrPgErrBit;
                return false;
            }
            sr |= SrEopBit;
            return true;
        }

        private ushort FilterWriteWord(ushort value, long offset)
        {
            ushort existing = flash.ReadWord(offset);
            if(!CheckFlashHalfwordProgramAllowed(offset, value, existing))
            {
                return existing;
            }
            return (ushort)(existing & value);
        }

        private uint FilterWriteDoubleWord(uint value, long offset)
        {
            ushort loExist = flash.ReadWord(offset);
            ushort hiExist = flash.ReadWord(offset + 2L);
            ushort loVal = (ushort)(value & 0xFFFFU);
            ushort hiVal = (ushort)((value >> 16) & 0xFFFFU);
            if(!CheckFlashHalfwordProgramAllowed(offset, loVal, loExist))
            {
                return (uint)loExist | ((uint)hiExist << 16);
            }
            ushort loNew = (ushort)(loExist & loVal);
            if(!CheckFlashHalfwordProgramAllowed(offset + 2L, hiVal, hiExist))
            {
                return (uint)loNew | ((uint)hiExist << 16);
            }
            ushort hiNew = (ushort)(hiExist & hiVal);
            return (uint)loNew | ((uint)hiNew << 16);
        }

        private byte FilterWriteByte(byte value, long offset)
        {
            // RM0091 FPEC forbids 8-bit byte writes to Flash
            byte existing = flash.ReadByte(offset);
            sr |= SrPgErrBit;
            return existing;
        }

        private const ulong FlashBaseAddr = 0x08000000UL;
        private const ulong MmuPageBytes = 0x1000UL;
        private const long FlashPageBytes = 2048L;
        private const long WrpUnitBytes = 4096L;

        private const uint FpecKey1 = 0x45670123U;
        private const uint FpecKey2 = 0xCDEF89ABU;

        private const uint SrPgErrBit = 1U << 2;
        private const uint SrWrprtErrBit = 1U << 4;
        private const uint SrEopBit = 1U << 5;
        private const uint SrClearMask = SrPgErrBit | SrWrprtErrBit | SrEopBit;

        private const uint CrPgBit = 1U << 0;
        private const uint CrPerBit = 1U << 1;
        private const uint CrOptPgBit = 1U << 4;
        private const uint CrOptErBit = 1U << 5;
        private const uint CrStrtBit = 1U << 6;
        private const uint CrLockBit = 1U << 7;
        private const uint CrOptWreBit = 1U << 9;

        private const uint DefaultObr = 0x00FFFF02U;

        private readonly IMachine machine;
        private readonly MappedMemory flash;
        private readonly Stm32F072OtpOptBlock otp;

        private bool hooksInstalled;
        private int keyState;
        private int optKeyState;
        private uint acr = 0x00000030U;
        private uint sr;
        private uint cr = CrLockBit;
        private uint ar;
        private uint obr = DefaultObr;
        private uint wrpr = 0xFFFFFFFFU;
    }
}
