//
// STMicroelectronics STM32F103 (ARM Cortex-M3, 1 KB/16-Bit FPEC, BKP->DR1..DR10) SoC Hardware Overlay
// for Headless Renode 1.17.0 End-to-End Testing
//
// Models RM0008 & PM0075 hardware peripherals with register-exact fidelity:
//   - BootAlias   (0x00000000): 512 KB boot alias window mirroring Main Flash at 0x08000000
//   - Dwt         (0xE0001000): ARMv7-M DWT_CTRL (+0x00) & monotonic DWT_CYCCNT (+0x04)
//   - OtpOptBlock (0x1FFFF000): Protected Keystore (+0x000), slot locks (+0x200),
//                               RM0008 Section 30.2 96-bit factory UID (+0x7E8 = 0x1FFFF7E8),
//                               and PM0075 Section 4.1 Option Bytes OB.WRP0..3 (+0x800 = 0x1FFFF800)
//   - Bkp         (0x40006C00): RM0008 Section 6.4 16-bit Backup Data Registers DR1..DR10 (+0x04..+0x28),
//                               strictly gated by RCC_APB1ENR (PWREN | BKPEN) AND PWR_CR.DBP!
//   - Pwr         (0x40007000): Power control register (PWR_CR.DBP backup domain write enable)
//   - Iwdg        (0x40003000): 40 kHz LSI Independent Watchdog latching RCC_CSR.IWDGRSTF
//   - GpioA       (0x40010800): GPIOA CRL (+0x00) & CRH (+0x04) for PA9/PA10 USART1 setup
//   - Adc1        (0x40012400): RM0008 Section 11.12 ADC1 (SR, CR1, CR2 CAL/ADON/TSVREFE/SWSTART, SMPR1, SQR1, SQR3, DR)
//   - Rcc         (0x40021000): Clock enables & persistent RCC_CSR warm-reset flags (IWDGRSTF / SFTRSTF)
//   - FlashCtrl   (0x40022000): PM0075 1 KB (1024 B) homogeneous page erase, 16-bit halfword NOR programming
//                               (1 -> 0 only, PGERR on 0 -> 1 overwrite, WRPRTERR on OB.WRP-protected Stage 0)
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
    public class Stm32f103BootAlias : IDoubleWordPeripheral, IWordPeripheral, IBytePeripheral, IKnownSize
    {
        public Stm32f103BootAlias(MappedMemory flash)
        {
            this.flash = flash;
        }

        public long Size => FlashSizeBytes;

        public uint ReadDoubleWord(long offset)
        {
            return flash.ReadDoubleWord(offset & (FlashSizeBytes - 1L));
        }

        public ushort ReadWord(long offset)
        {
            return flash.ReadWord(offset & (FlashSizeBytes - 1L));
        }

        public byte ReadByte(long offset)
        {
            return flash.ReadByte(offset & (FlashSizeBytes - 1L));
        }

        public void WriteDoubleWord(long offset, uint value)
        {
        }

        public void WriteWord(long offset, ushort value)
        {
        }

        public void WriteByte(long offset, byte value)
        {
        }

        public void Reset()
        {
        }

        private const long FlashSizeBytes = 0x80000L;

        private readonly MappedMemory flash;
    }

    public class Stm32f103Dwt : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x100;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // DWT_CTRL
                return ctrl;
            case 0x04: // DWT_CYCCNT
                if((ctrl & CyccntEnaBit) != 0U)
                {
                    cyccnt += 37U;
                }
                return cyccnt;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00:
                ctrl = value;
                break;
            case 0x04:
                cyccnt = value;
                break;
            }
        }

        public void Reset()
        {
            ctrl = 0x40000000U;
            cyccnt = 0U;
        }

        private const uint CyccntEnaBit = 1U << 0;

        private uint ctrl = 0x40000000U;
        private uint cyccnt;
    }

    public class Stm32f103Rcc : IDoubleWordPeripheral, IKnownSize, IGPIOReceiver
    {
        public Stm32f103Rcc(IMachine machine)
        {
            this.machine = machine;
            csr = CsrPorRstfBit | CsrPinRstfBit | CsrLsiRdyBit;
        }

        public long Size => 0x400;

        public uint Apb1Enr => apb1enr;

        public uint Apb2Enr => apb2enr;

        public uint Csr
        {
            get => csr;
            set => csr = value;
        }

        public bool IsPwrClockEnabled => (apb1enr & Apb1EnrPwrEnBit) != 0U;

        public bool IsBkpClockEnabled => (apb1enr & Apb1EnrBkpEnBit) != 0U;

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
            }
        }

        public void Reset()
        {
            cr = 0x00000083U;
            cfgr = 0U;
            apb2enr = 0U;
            apb1enr = 0U;
            // RM0008 Section 7.3.10: RCC_CSR reset flags persist across warm resets until cleared via RMVF.
        }

        private const uint Apb1EnrBkpEnBit = 1U << 27;
        private const uint Apb1EnrPwrEnBit = 1U << 28;

        private const uint CsrLsiRdyBit = 1U << 1;
        private const uint CsrRmvfBit = 1U << 24;
        private const uint CsrPinRstfBit = 1U << 26;
        private const uint CsrPorRstfBit = 1U << 27;
        private const uint CsrSftRstfBit = 1U << 28;
        private const uint CsrIwdgRstfBit = 1U << 29;
        private const uint CsrResetFlagsMask = 0xFC000000U;

        private readonly IMachine machine;
        private uint cr = 0x00000083U;
        private uint cfgr;
        private uint apb2enr;
        private uint apb1enr;
        private uint csr;
    }

    public class Stm32f103Pwr : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32f103Pwr(Stm32f103Rcc rcc = null)
        {
            this.rcc = rcc;
        }

        public long Size => 0x400;

        public bool IsBackupWriteEnabled =>
            (rcc == null || rcc.IsPwrClockEnabled) && ((cr & PwrCrDbpBit) != 0U);

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
            if(rcc != null && !rcc.IsPwrClockEnabled)
            {
                return;
            }
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
            cr = 0U; // RM0008 Section 5.4.1: PWR_CR.DBP resets to 0 on every system reset
            csr = 0U;
        }

        private const uint PwrCrDbpBit = 1U << 8;

        private readonly Stm32f103Rcc rcc;
        private uint cr;
        private uint csr;
    }

    public class Stm32f103Bkp : IDoubleWordPeripheral, IWordPeripheral, IKnownSize
    {
        public Stm32f103Bkp(Stm32f103Pwr pwr = null, Stm32f103Rcc rcc = null)
        {
            this.pwr = pwr;
            this.rcc = rcc;
        }

        public long Size => 0x400;

        public uint BlockedWrites { get; private set; }

        public ushort Dr1 => dr[0];
        public ushort Dr2 => dr[1];
        public ushort Dr3 => dr[2];
        public ushort Dr4 => dr[3];
        public ushort Dr5 => dr[4];

        private bool CanReadBkp => rcc == null || rcc.IsBkpClockEnabled;

        private bool CanWriteBkp =>
            (rcc == null || (rcc.IsBkpClockEnabled && rcc.IsPwrClockEnabled)) &&
            (pwr == null || pwr.IsBackupWriteEnabled);

        public uint ReadDoubleWord(long offset)
        {
            if(!CanReadBkp)
            {
                return 0U;
            }
            if(offset >= Dr1Offset && offset <= Dr10Offset && ((offset & 0x3L) == 0L))
            {
                int idx = (int)((offset - Dr1Offset) >> 2);
                // RM0008 Section 6.4.1: Bits [31:16] are reserved and always read as 0x0000!
                return (uint)dr[idx];
            }
            return 0U;
        }

        public ushort ReadWord(long offset)
        {
            if(!CanReadBkp)
            {
                return 0;
            }
            if(offset >= Dr1Offset && offset <= Dr10Offset && ((offset & 0x3L) == 0L))
            {
                int idx = (int)((offset - Dr1Offset) >> 2);
                return dr[idx];
            }
            return 0;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(offset >= Dr1Offset && offset <= Dr10Offset && ((offset & 0x3L) == 0L))
            {
                WriteDrSlot((int)((offset - Dr1Offset) >> 2), (ushort)(value & 0xFFFFU));
            }
        }

        public void WriteWord(long offset, ushort value)
        {
            if(offset >= Dr1Offset && offset <= Dr10Offset && ((offset & 0x3L) == 0L))
            {
                WriteDrSlot((int)((offset - Dr1Offset) >> 2), value);
            }
        }

        private void WriteDrSlot(int idx, ushort value)
        {
            if(!CanWriteBkp)
            {
                BlockedWrites++;
                this.Log(LogLevel.Warning, "Blocked BKP->DR{0} write while PWR_CR.DBP=0 or BKPEN/PWREN=0", idx + 1);
                return;
            }
            dr[idx] = value;
        }

        public void Reset()
        {
            // RM0008 Section 6.1: Backup data registers DR1..DR10 are not reset by System or IWDG resets.
        }

        private const long Dr1Offset = 0x04L;
        private const long Dr10Offset = 0x28L;

        private readonly Stm32f103Pwr pwr;
        private readonly Stm32f103Rcc rcc;
        private readonly ushort[] dr = new ushort[10];
    }

    public class Stm32f103GpioA : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00:
                return crl;
            case 0x04:
                return crh;
            case 0x08:
                return idr;
            case 0x0C:
                return odr;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00:
                crl = value;
                break;
            case 0x04:
                crh = value;
                break;
            case 0x0C:
                odr = value & 0xFFFFU;
                break;
            case 0x10: // BSRR
                odr = ((odr | (value & 0xFFFFU)) & ~((value >> 16) & 0xFFFFU)) & 0xFFFFU;
                break;
            }
        }

        public void Reset()
        {
            crl = 0x44444444U;
            crh = 0x44444444U;
            idr = 0x00000400U;
            odr = 0U;
        }

        private uint crl = 0x44444444U;
        private uint crh = 0x44444444U;
        private uint idr = 0x00000400U;
        private uint odr;
    }

    public class Stm32f103Iwdg : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32f103Iwdg(IMachine machine, Stm32f103Rcc rcc = null)
        {
            this.rcc = rcc;
            timer = new LimitTimer(
                machine.ClockSource,
                40000UL,
                this,
                "stm32f1_iwdg_timer",
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

        private readonly Stm32f103Rcc rcc;
        private readonly LimitTimer timer;
        private bool unlocked;
        private bool running;
        private uint pr;
        private uint rlr = 0xFFFU;
    }

    public class Stm32f103Adc1 : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32f103Adc1()
        {
            byte[] seedBytes = Guid.NewGuid().ToByteArray();
            ulong s0 = BitConverter.ToUInt64(seedBytes, 0);
            ulong s1 = BitConverter.ToUInt64(seedBytes, 8);
            state = s0 ^ s1 ^ 0x9E3779B97F4A7C15UL;
            if(state == 0UL)
            {
                state = 0xF103CAFEBABE5678UL;
            }
        }

        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x00: // SR
                return sr;
            case 0x04: // CR1
                return cr1;
            case 0x08: // CR2
                return cr2;
            case 0x0C: // SMPR1
                return smpr1;
            case 0x2C: // SQR1
                return sqr1;
            case 0x34: // SQR3
                return sqr3;
            case 0x4C: // DR (RM0008 Section 11.12.14: reading DR clears EOC)
                sr &= ~AdcSrEocBit;
                return dr;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x00: // SR (rc_w0)
                sr &= value;
                break;
            case 0x04: // CR1
                cr1 = value;
                break;
            case 0x08: // CR2
                // RM0008 Section 11.3.1: CAL bit clears automatically once calibration finishes
                bool wasAdon = (cr2 & AdcCr2AdonBit) != 0U;
                cr2 = value & ~(AdcCr2CalBit | AdcCr2SwstartBit);
                bool nowAdon = (cr2 & AdcCr2AdonBit) != 0U;
                bool startReq = ((value & AdcCr2SwstartBit) != 0U) || (wasAdon && ((value & AdcCr2AdonBit) != 0U) && ((value & AdcCr2CalBit) == 0U));
                if(nowAdon && startReq)
                {
                    dr = DrawSensorSample(sqr3 & 0x1FU);
                    sr |= AdcSrEocBit;
                }
                break;
            case 0x0C: // SMPR1
                smpr1 = value;
                break;
            case 0x2C: // SQR1
                sqr1 = value;
                break;
            case 0x34: // SQR3
                sqr3 = value;
                break;
            }
        }

        public void Reset()
        {
            sr = 0U;
            cr1 = 0U;
            cr2 = 0U;
            smpr1 = 0U;
            sqr1 = 0U;
            sqr3 = 0U;
            dr = 0U;
            lastSample = 0U;
        }

        private uint DrawSensorSample(uint channel)
        {
            for(int i = 0; i < 8; i++)
            {
                state += 0x9E3779B97F4A7C15UL + channel;
                ulong z = state;
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
                z ^= z >> 31;
                // 12-bit STM32F103 ADC conversion result with realistic internal sensor baseline + LSB noise
                uint baseline = (channel == 16U) ? 0x06E0U : 0x05D0U;
                uint sample = (baseline ^ (uint)(z & 0x01FFUL)) & 0x0FFFU;
                if(sample != 0U && sample != lastSample)
                {
                    lastSample = sample;
                    return sample;
                }
            }
            lastSample = (lastSample ^ 0x035AU) & 0x0FFFU;
            return lastSample;
        }

        private const uint AdcSrEocBit = 1U << 1;
        private const uint AdcCr2AdonBit = 1U << 0;
        private const uint AdcCr2CalBit = 1U << 2;
        private const uint AdcCr2SwstartBit = 1U << 22;

        private ulong state;
        private uint sr;
        private uint cr1;
        private uint cr2;
        private uint smpr1;
        private uint sqr1;
        private uint sqr3;
        private uint dr;
        private uint lastSample;
    }

    public class Stm32f103OtpOptBlock : IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IKnownSize
    {
        public Stm32f103OtpOptBlock()
        {
            ResetToDefaultErased();
        }

        public long Size => TotalBlockBytes;

        internal Stm32f103FlashController FlashController { get; set; }

        public void ResetToDefaultErased()
        {
            for(int i = 0; i < TotalBlockBytes; i++)
            {
                rawBytes[i] = 0xFF;
            }
            byte[] defaultUid = { 0x31, 0x03, 0xF1, 0x03, 0x53, 0x54, 0x4D, 0x33, 0xAA, 0x55, 0x10, 0x3E };
            Array.Copy(defaultUid, 0, rawBytes, UidOffset, defaultUid.Length);

            // PM0075 Section 4.1 factory Option Bytes at 0x1FFFF800..0x1FFFF80F:
            // [0] RDP = 0xA5 (~0x5A, unprotected), [1] USER = 0xFF, [2..3] Data0..1 = 0xFF, [4..7] WRP0..3 = 0xFF
            WriteRawOptionHalfword(0, 0xA5);
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

            // Protected Keystore payload & lock window: 0x1FFFF000 .. 0x1FFFF207
            if(offset < OtpEndOffset)
            {
                if(FlashController == null || !FlashController.IsPgEnabledAndUnlocked)
                {
                    FlashController?.RaisePgErr();
                    return;
                }

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

            // RM0008 Section 30.2: 96-bit factory UID at +0x7E8 (0x1FFFF7E8) is read-only silicon ROM
            FlashController?.RaiseWrprtErr();
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            WriteWord(offset, (ushort)(value & 0xFFFFU));
            WriteWord(offset + 2L, (ushort)((value >> 16) & 0xFFFFU));
        }

        public void Reset()
        {
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
        private const int UidOffset = 0x7E8; // 0x1FFFF7E8 on STM32F103!
        private const int OptionBytesOffset = 0x800;
        private const int OptionHalfwordCount = 8;
        private const int OptionBytesSize = OptionHalfwordCount * 2;
        private const int TotalBlockBytes = 0x1000;

        private readonly byte[] rawBytes = new byte[TotalBlockBytes];
    }

    public class Stm32f103FlashController : IDoubleWordPeripheral, IKnownSize
    {
        public Stm32f103FlashController(
            IMachine machine,
            MappedMemory flash,
            Stm32f103OtpOptBlock otp = null)
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

        public uint PgErrors { get; private set; }

        public uint PageErases { get; private set; }

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
            PgErrors++;
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
            case 0x1C: // OBR (RDP unprotected, OPTERR=0)
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

            case 0x08: // OPTKEYR
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

            case 0x0C: // SR (rc_w1 on EOP, WRPRTERR, PGERR)
                sr &= ~(value & SrClearMask);
                break;

            case 0x10: // CR
                if((cr & CrLockBit) != 0U)
                {
                    return;
                }
                if((value & CrLockBit) != 0U)
                {
                    cr = CrLockBit;
                    keyState = 0;
                    optKeyState = 0;
                    return;
                }

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
                RaisePgErr();
                return;
            }

            // True 1 KB (1024-byte) homogeneous FPEC page erase!
            long pageOffset = (long)(targetAddr - (uint)FlashBaseAddr) & ~(FlashPageBytes - 1L);
            if(IsOffsetWriteProtected(pageOffset))
            {
                BlockedOperations++;
                sr |= SrWrprtErrBit;
                this.Log(LogLevel.Warning, "OB.WRP blocked 1 KB page erase at 0x{0:X8} (WRPR=0x{1:X8})", targetAddr, wrpr);
                return;
            }

            PageErases++;
            flash.SetRange(pageOffset, FlashPageBytes, 0xFF);
            sr |= SrEopBit;
        }

        private bool IsOffsetWriteProtected(long offset)
        {
            // RM0008 Section 3.3.3: Each WRPR bit protects four 1 KB pages (4 KB = 4096 B), active-low (0 = protected).
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
                RaisePgErr();
                return false;
            }
            if(!IsPgEnabledAndUnlocked)
            {
                RaisePgErr();
                return false;
            }
            if(IsOffsetWriteProtected(offset))
            {
                BlockedOperations++;
                sr |= SrWrprtErrBit;
                this.Log(LogLevel.Warning, "OB.WRP blocked halfword write at +0x{0:X5} (WRPR=0x{1:X8})", offset, wrpr);
                return false;
            }
            // PM0075 Section 2.3.1 NOR flash rule: 0 -> 1 bit transitions without page erase trigger PGERR!
            if((value & (ushort)~existing) != 0)
            {
                RaisePgErr();
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
            // PM0075 Section 2.3.1: FPEC strictly rejects 8-bit byte writes to Flash
            byte existing = flash.ReadByte(offset);
            RaisePgErr();
            return existing;
        }

        private const ulong FlashBaseAddr = 0x08000000UL;
        private const ulong MmuPageBytes = 0x1000UL;
        private const long FlashPageBytes = 1024L; // 1 KB FPEC erase page!
        private const long WrpUnitBytes = 4096L;   // 4 x 1 KB pages per WRP bit

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

        private const uint DefaultObr = 0x03FFFFFCU;

        private readonly IMachine machine;
        private readonly MappedMemory flash;
        private readonly Stm32f103OtpOptBlock otp;

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
