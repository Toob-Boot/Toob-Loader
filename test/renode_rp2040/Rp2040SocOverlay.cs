//
// Raspberry Pi RP2040 Dual Cortex-M0+ SoC Hardware Overlay for Renode 1.17.0 E2E Testing
//
// Models authentic RP2040 hardware blocks required for full-system Toob-Boot verification:
//   - RP2040 Mask-ROM (0x00000000): Real ARMv6-M Thumb BootROM executing 256-byte boot2 copy
//                                   to SRAM5 (0x20041F00), non-reflected MPEG-2 CRC-32 verify
//                                   (poly=0x04C11DB7, init=0xFFFFFFFF, xorout=0), fail-closed
//                                   CRC-mismatch halt, Core-1 WFE park, and ROM lookup table.
//   - XIP_CTRL       (0x14000000): XIP enable, cache FLUSH, and STAT.FLUSH_READY.
//   - SSI + W25Q16JV (0x18000000): DW_apb_ssi + 2MB QSPI NOR Flash (06h WREN, 05h RDSR1,
//                                   01h WRSR with SRP0+SEC+TB+BPx lower-block lock, 4Bh 64-bit
//                                   Unique ID, 20h 4KB Sector Erase, 02h 1->0 Page Program,
//                                   and protected OTP keystore sector 0x1FF000).
//   - PSM            (0x40010000): FRCE_ON, FRCE_OFF (PROC1 Core-1 isolation), WDSEL.
//   - TIMER          (0x40054000): 1 MHz 64-bit monotonic microsecond timer (TIMERAWH/TIMERAWL).
//   - WATCHDOG       (0x40058000): 2 MHz (RP2040-E1) countdown timer, CTRL.TRIGGER, REASON
//                                   (TIMER/FORCE), TICK, and warm-reset-retained SCRATCH[0..7].
//   - ROSC           (0x40060000): Ring oscillator STATUS.STABLE + RANDOMBIT entropy source.
//   - VREG_CHIP_RESET(0x40064000): CHIP_RESET (HAD_POR / HAD_PSM_RESTART W1C) + SYSRESETREQ.
//   - SIO            (0xD0000000): Per-core CPUID (0 for Core 0, 1 for Core 1).
//

using System;
using System.Collections.Generic;
using System.IO;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.IRQControllers;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.Timers;
using Antmicro.Renode.Time;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class Rp2040XipCtrl : IDoubleWordPeripheral, IKnownSize
    {
        public Rp2040XipCtrl(IMachine machine)
        {
            this.machine = machine;
            ctrl = 0x01U;
        }

        public long Size => 0x100;

        public uint FlushCount { get; private set; }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // CTRL
                return ctrl;
            case 0x004: // FLUSH
                return 0U;
            case 0x008: // STAT (FIFO_EMPTY | FLUSH_READY)
                return 0x03U;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x000:
                ctrl = value & 0x0FU;
                break;
            case 0x004:
                FlushCount++;
                break;
            }
        }

        public void Reset()
        {
            ctrl = 0x01U;
        }

        private readonly IMachine machine;
        private uint ctrl;
    }

    public class Rp2040SsiNor : IDoubleWordPeripheral, IKnownSize
    {
        public Rp2040SsiNor(IMachine machine, MappedMemory xipFlash, Rp2040XipCtrl xipCtrl = null)
        {
            this.machine = machine;
            this.xipFlash = xipFlash;
            this.xipCtrl = xipCtrl;
        }

        public long Size => 0x1000;

        public uint StatusRegister1 => (uint)(sr1NonVolatile | (welLatch ? 0x02 : 0x00));

        public uint BlockedOperations { get; private set; }

        public uint BlockedDirectXipWrites { get; private set; }

        public void InstallXipWriteProtection()
        {
            if(hooksInstalled)
            {
                return;
            }
            var sysbus = (SystemBus)machine.SystemBus;
            // Trap direct CPU stores to Stage 0 XIP window (0x10000000..0x10007FFF) via IO hooks;
            // external QSPI NOR flash can only be programmed/erased through SSI SPI commands.
            for(ulong addr = XipBaseAddress; addr < XipBaseAddress + 0x8000UL; addr += 0x1000UL)
            {
                sysbus.SetPageAccessViaIo(addr);
            }
            sysbus.SetHookBeforePeripheralWrite<uint>(xipFlash, RejectDirectWriteDoubleWord);
            sysbus.SetHookBeforePeripheralWrite<ushort>(xipFlash, RejectDirectWriteWord);
            sysbus.SetHookBeforePeripheralWrite<byte>(xipFlash, RejectDirectWriteByte);
            hooksInstalled = true;
        }

        public void SaveFlashRange(string path, uint offset, uint length)
        {
            byte[] data = xipFlash.ReadBytes((long)offset, (int)length);
            File.WriteAllBytes(path, data);
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // CTRLR0
                return ctrlr0;
            case 0x004: // CTRLR1
                return ctrlr1;
            case 0x008: // SSIENR
                return ssienr;
            case 0x014: // BAUDR
                return baudr;
            case 0x028: // SR (TFE=0x04 | TFNF=0x02 | RFNE=0x08)
                return 0x06U | (rxQueue.Count > 0 ? 0x08U : 0x00U);
            case 0x060: // DR0
                return rxQueue.Count > 0 ? (uint)rxQueue.Dequeue() : 0U;
            case 0x0F4: // SPI_CTRLR0
                return spiCtrlr0;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x000:
                ctrlr0 = value;
                break;
            case 0x004:
                ctrlr1 = value;
                break;
            case 0x008:
                HandleSsiEnableChange(value & 0x01U);
                break;
            case 0x014:
                baudr = value & 0xFFFFU;
                break;
            case 0x060:
                if(ssienr != 0U && spiCtrlr0 == 0U)
                {
                    ProcessSpiByte((byte)(value & 0xFFU));
                }
                break;
            case 0x0F4:
                spiCtrlr0 = value;
                break;
            }
        }

        public void Reset()
        {
            ctrlr0 = 0x001F0300U;
            ctrlr1 = 0U;
            ssienr = 1U;
            baudr = 4U;
            spiCtrlr0 = 0x03000218U;
            welLatch = false;
            cmdByte = 0;
            byteIndex = 0;
            addr24 = 0U;
            rxQueue.Clear();
            // Note: sr1NonVolatile (SRP0 | SEC | TB | BP2..0) is non-volatile NOR Status Register 1
            // and persists across warm resets just like physical Winbond W25Q16JV silicon.
            if(hooksInstalled)
            {
                var sysbus = (SystemBus)machine.SystemBus;
                for(ulong addr = XipBaseAddress; addr < XipBaseAddress + 0x8000UL; addr += 0x1000UL)
                {
                    sysbus.SetPageAccessViaIo(addr);
                }
            }
        }

        private void HandleSsiEnableChange(uint nextEn)
        {
            if(ssienr == 1U && nextEn == 0U)
            {
                if(cmdByte == CmdPageProgram)
                {
                    welLatch = false;
                }
                cmdByte = 0;
                byteIndex = 0;
                addr24 = 0U;
                rxQueue.Clear();
            }
            else if(ssienr == 0U && nextEn == 1U)
            {
                cmdByte = 0;
                byteIndex = 0;
                addr24 = 0U;
                rxQueue.Clear();
            }
            ssienr = nextEn;
        }

        private void ProcessSpiByte(byte tx)
        {
            if(byteIndex == 0)
            {
                cmdByte = tx;
                rxQueue.Enqueue(0x00);
                if(cmdByte == CmdWriteEnable)
                {
                    welLatch = true;
                }
                else if(cmdByte == CmdWriteDisable)
                {
                    welLatch = false;
                }
                byteIndex = 1;
                return;
            }

            switch(cmdByte)
            {
            case CmdReadStatus1:
                rxQueue.Enqueue((byte)(sr1NonVolatile | (welLatch ? 0x02 : 0x00)));
                break;

            case CmdReadUniqueId:
                if(byteIndex <= 4)
                {
                    rxQueue.Enqueue(0x00);
                }
                else
                {
                    int uidIdx = byteIndex - 5;
                    rxQueue.Enqueue(uidIdx < UniqueIdBytes.Length ? UniqueIdBytes[uidIdx] : (byte)0x00);
                }
                break;

            case CmdWriteStatus1:
                rxQueue.Enqueue(0x00);
                if(byteIndex == 1 && welLatch)
                {
                    welLatch = false;
                    // Once SRP0 (bit 7 = 0x80) is set with hardware /WP asserted, SR1 is locked!
                    if((sr1NonVolatile & 0x80) != 0 && (tx & 0xFC) != sr1NonVolatile)
                    {
                        BlockedOperations++;
                        this.Log(LogLevel.Warning, "SPI NOR SRP0 blocked WRSR attempt (cur=0x{0:X2}, req=0x{1:X2})", sr1NonVolatile, tx);
                    }
                    else
                    {
                        sr1NonVolatile = (byte)(tx & 0xFC);
                    }
                }
                break;

            case CmdReadData:
                if(byteIndex <= 3)
                {
                    addr24 = (addr24 << 8) | tx;
                    rxQueue.Enqueue(0x00);
                }
                else
                {
                    uint rdOff = (addr24 + (uint)(byteIndex - 4)) & FlashAddrMask;
                    rxQueue.Enqueue(xipFlash.ReadByte((long)rdOff));
                }
                break;

            case CmdSectorErase4K:
                addr24 = (addr24 << 8) | tx;
                rxQueue.Enqueue(0x00);
                if(byteIndex == 3 && welLatch)
                {
                    welLatch = false;
                    uint sectorAddr = addr24 & 0x1FF000U;
                    if(sectorAddr >= OtpKeystoreOffset)
                    {
                        BlockedOperations++;
                        this.Log(LogLevel.Warning, "Blocked 20h Sector Erase on OTP keystore sector 0x{0:X6}", sectorAddr);
                    }
                    else if(IsOffsetBpProtected(sectorAddr))
                    {
                        BlockedOperations++;
                        this.Log(LogLevel.Warning, "SPI NOR BPx blocked 20h Sector Erase at 0x{0:X6} (SR1=0x{1:X2})", sectorAddr, sr1NonVolatile);
                    }
                    else
                    {
                        xipFlash.SetRange((long)sectorAddr, 0x1000L, 0xFF);
                    }
                }
                break;

            case CmdPageProgram:
                if(byteIndex <= 3)
                {
                    addr24 = (addr24 << 8) | tx;
                    rxQueue.Enqueue(0x00);
                }
                else
                {
                    rxQueue.Enqueue(0x00);
                    if(welLatch)
                    {
                        uint pageBase = addr24 & 0x1FFF00U;
                        uint pageOff = (addr24 + (uint)(byteIndex - 4)) & 0xFFU;
                        uint target = pageBase | pageOff;
                        if(IsOffsetBpProtected(target))
                        {
                            BlockedOperations++;
                            this.Log(LogLevel.Warning, "SPI NOR BPx blocked 02h Page Program at 0x{0:X6} (SR1=0x{1:X2})", target, sr1NonVolatile);
                        }
                        else if(target < FlashTotalBytes)
                        {
                            byte existing = xipFlash.ReadByte((long)target);
                            xipFlash.WriteByte((long)target, (byte)(existing & tx));
                        }
                    }
                }
                break;

            default:
                rxQueue.Enqueue(0x00);
                break;
            }

            byteIndex++;
        }

        private bool IsOffsetBpProtected(uint offset)
        {
            uint protectedBytes = GetProtectedLowerBytes(sr1NonVolatile);
            return offset < protectedBytes;
        }

        private static uint GetProtectedLowerBytes(byte sr1)
        {
            int bp = (sr1 >> 2) & 0x07;
            if(bp == 0)
            {
                return 0U;
            }
            bool tbBottom = (sr1 & 0x20) != 0;
            bool sec4K = (sr1 & 0x40) != 0;
            if(!tbBottom)
            {
                return 0U;
            }
            if(sec4K)
            {
                switch(bp)
                {
                case 1:
                    return 4U * 1024U;
                case 2:
                    return 8U * 1024U;
                case 3:
                    return 16U * 1024U;
                default:
                    return 32U * 1024U;
                }
            }
            uint bytes = 65536U << (bp - 1);
            return bytes > FlashTotalBytes ? FlashTotalBytes : bytes;
        }

        private uint RejectDirectWriteDoubleWord(uint value, long offset)
        {
            BlockedDirectXipWrites++;
            return xipFlash.ReadDoubleWord(offset);
        }

        private ushort RejectDirectWriteWord(ushort value, long offset)
        {
            BlockedDirectXipWrites++;
            return xipFlash.ReadWord(offset);
        }

        private byte RejectDirectWriteByte(byte value, long offset)
        {
            BlockedDirectXipWrites++;
            return xipFlash.ReadByte(offset);
        }

        private const ulong XipBaseAddress = 0x10000000UL;
        private const uint FlashTotalBytes = 0x00200000U;
        private const uint FlashAddrMask = 0x001FFFFFU;
        private const uint OtpKeystoreOffset = 0x001FF000U;

        private const byte CmdWriteStatus1 = 0x01;
        private const byte CmdPageProgram = 0x02;
        private const byte CmdReadData = 0x03;
        private const byte CmdWriteDisable = 0x04;
        private const byte CmdReadStatus1 = 0x05;
        private const byte CmdWriteEnable = 0x06;
        private const byte CmdSectorErase4K = 0x20;
        private const byte CmdReadUniqueId = 0x4B;

        private static readonly byte[] UniqueIdBytes = new byte[]
        {
            0xE6, 0x61, 0x41, 0x03, 0xE7, 0x20, 0x40, 0x01
        };

        private readonly IMachine machine;
        private readonly MappedMemory xipFlash;
        private readonly Rp2040XipCtrl xipCtrl;
        private readonly Queue<byte> rxQueue = new Queue<byte>();

        private bool hooksInstalled;
        private uint ctrlr0 = 0x001F0300U;
        private uint ctrlr1;
        private uint ssienr = 1U;
        private uint baudr = 4U;
        private uint spiCtrlr0 = 0x03000218U;

        private byte sr1NonVolatile;
        private bool welLatch;
        private byte cmdByte;
        private int byteIndex;
        private uint addr24;
    }

    public class Rp2040Psm : IDoubleWordPeripheral, IKnownSize
    {
        public Rp2040Psm(CortexM cpu1 = null)
        {
            this.cpu1 = cpu1;
        }

        public long Size => 0x100;

        public uint Wdsel { get; private set; }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // FRCE_ON
                return frceOn;
            case 0x004: // FRCE_OFF
                return frceOff;
            case 0x008: // WDSEL
                return Wdsel;
            case 0x00C: // DONE
                return 0x0001FFFFU & ~frceOff;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x000:
                frceOn = value;
                break;
            case 0x004:
                frceOff = value;
                if(cpu1 != null && (frceOff & (1U << 16)) != 0U)
                {
                    cpu1.IsHalted = true;
                }
                break;
            case 0x008:
                Wdsel = value;
                break;
            }
        }

        public void Reset()
        {
            frceOn = 0U;
            frceOff = 0U;
            Wdsel = 0U;
        }

        private readonly CortexM cpu1;
        private uint frceOn;
        private uint frceOff;
    }

    public class Rp2040Timer : IDoubleWordPeripheral, IKnownSize
    {
        public Rp2040Timer(IMachine machine)
        {
            this.machine = machine;
        }

        public long Size => 0x100;

        public uint ReadDoubleWord(long offset)
        {
            ulong us = (ulong)machine.LocalTimeSource.ElapsedVirtualTime.TotalMicroseconds;
            switch(offset)
            {
            case 0x00C: // TIMELR
            case 0x028: // TIMERAWL
                return (uint)(us & 0xFFFFFFFFUL);
            case 0x008: // TIMEHR
            case 0x024: // TIMERAWH
                return (uint)(us >> 32);
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
        }

        public void Reset()
        {
        }

        private readonly IMachine machine;
    }

    public class Rp2040Watchdog : IDoubleWordPeripheral, IKnownSize
    {
        public Rp2040Watchdog(IMachine machine)
        {
            this.machine = machine;
            // RP2040-E1 decrements LOAD at 2 ticks per microsecond (2 MHz).
            countdown = new LimitTimer(
                machine.ClockSource,
                2000000,
                this,
                "rp2040_wdt",
                limit: 0x00FFFFFFUL,
                direction: Direction.Descending,
                enabled: false,
                workMode: WorkMode.OneShot,
                eventEnabled: true,
                autoUpdate: false);
            countdown.LimitReached += OnWatchdogExpired;
        }

        public long Size => 0x100;

        public void LatchForceReason()
        {
            reason = ReasonForceBit;
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // CTRL
                return (ctrl & 0x40000000U) | ((uint)countdown.Value & 0x00FFFFFFU);
            case 0x004: // LOAD
                return 0U;
            case 0x008: // REASON
                return reason;
            case 0x00C:
            case 0x010:
            case 0x014:
            case 0x018:
            case 0x01C:
            case 0x020:
            case 0x024:
            case 0x028:
                return scratch[(offset - 0x00C) >> 2];
            case 0x02C: // TICK
                return ((tick & (1U << 9)) != 0U) ? (tick | (1U << 10)) : tick;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            // RP2040 atomic register aliases: +0x1000 XOR, +0x2000 SET, +0x3000 CLR
            switch(offset)
            {
            case 0x000: // CTRL
                if((value & CtrlTriggerBit) != 0U)
                {
                    countdown.Enabled = false;
                    reason = ReasonForceBit;
                    this.Log(LogLevel.Info, "WATCHDOG.CTRL.TRIGGER asserted; requesting warm reset (REASON=0x{0:X2})", reason);
                    machine.RequestReset();
                    return;
                }
                ctrl = value & CtrlEnableBit;
                countdown.Enabled = (ctrl & CtrlEnableBit) != 0U;
                break;
            case 0x004: // LOAD
                uint loadVal = value & 0x00FFFFFFU;
                if(loadVal == 0U)
                {
                    loadVal = 1U;
                }
                countdown.Value = loadVal;
                break;
            case 0x00C:
            case 0x010:
            case 0x014:
            case 0x018:
            case 0x01C:
            case 0x020:
            case 0x024:
            case 0x028:
                scratch[(offset - 0x00C) >> 2] = value;
                break;
            case 0x02C: // TICK
                tick = value & 0x03FFU;
                break;
            }
        }

        public void Reset()
        {
            ctrl = 0U;
            countdown.Enabled = false;
            countdown.Value = 0x00FFFFFFUL;
            // WATCHDOG->SCRATCH[0..7] and WATCHDOG->REASON persist across warm resets!
        }

        private void OnWatchdogExpired()
        {
            countdown.Enabled = false;
            ctrl = 0U;
            reason = ReasonTimerBit;
            this.Log(LogLevel.Info, "WATCHDOG timer expired; latching REASON.TIMER=1 and requesting warm reset.");
            machine.RequestReset();
        }

        private const uint CtrlTriggerBit = 1U << 31;
        private const uint CtrlEnableBit = 1U << 30;
        private const uint ReasonTimerBit = 0x01U;
        private const uint ReasonForceBit = 0x02U;

        private readonly IMachine machine;
        private readonly LimitTimer countdown;
        private readonly uint[] scratch = new uint[8];
        private uint ctrl;
        private uint reason;
        private uint tick = 0x020CU;
    }

    public class Rp2040Rosc : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x100;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // CTRL
                return ctrl;
            case 0x018: // STATUS (STABLE | ENABLED)
                return 0x80001000U;
            case 0x01C: // RANDOMBIT
                prngState ^= prngState >> 12;
                prngState ^= prngState << 25;
                prngState ^= prngState >> 27;
                ulong mixed = prngState * 2685821657736338717UL;
                return (uint)((mixed >> 63) & 1UL);
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(offset == 0x000)
            {
                ctrl = value;
            }
        }

        public void Reset()
        {
            ctrl = 0x00FABFA0U;
        }

        private uint ctrl = 0x00FABFA0U;
        private ulong prngState = 0x9E3779B97F4A7C15UL;
    }

    public class Rp2040VregChipReset : IDoubleWordPeripheral, IKnownSize, IGPIOReceiver
    {
        public Rp2040VregChipReset(
            IMachine machine,
            MappedMemory rom,
            Rp2040Watchdog watchdog,
            Rp2040SsiNor ssi,
            NVIC nvic0 = null)
        {
            this.machine = machine;
            this.rom = rom;
            this.watchdog = watchdog;
            this.ssi = ssi;
            this.nvic0 = nvic0;
            chipReset = ChipResetHadPorBit;
        }

        public long Size => 0x100;

        public uint BootRomStatus { get; private set; }

        public uint BootRomComputedCrc { get; private set; }

        public uint MpuCtrl => mpuCtrl;

        public uint MpuRbar => mpuRbar[mpuRnr & 0x7U];

        public uint MpuRasr => mpuRasr[mpuRnr & 0x7U];

        public void InstallBootRomAndHooks()
        {
            for(int i = 0; i < BootRomWords.Length; i++)
            {
                rom.WriteDoubleWord((long)i * 4L, BootRomWords[i]);
            }
            ssi?.InstallXipWriteProtection();
            if(nvic0 != null && !mpuHooksInstalled)
            {
                var sysbus = (SystemBus)machine.SystemBus;
                sysbus.SetHookAfterPeripheralRead<uint>(nvic0, ReadNvicOrMpu);
                sysbus.SetHookBeforePeripheralWrite<uint>(nvic0, WriteNvicOrMpu);
                mpuHooksInstalled = true;
            }
        }

        public void OnGPIO(int number, bool value)
        {
            if(number == 0 && value)
            {
                watchdog?.LatchForceReason();
                chipReset |= ChipResetHadPsmRestartBit;
                this.Log(LogLevel.Info, "SYSRESETREQ latched CHIP_RESET=0x{0:X8}; requesting warm reset.", chipReset);
                machine.RequestReset();
            }
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // VREG
                return 0x000010B1U;
            case 0x004: // BOD
                return 0x00000091U;
            case 0x008: // CHIP_RESET
                return chipReset;
            case 0x010: // BootROM CRC verification status (0x600DC2C0 / 0xBAD0C2C0)
                return BootRomStatus;
            case 0x014: // BootROM computed MPEG-2 CRC-32 of boot2[0..252]
                return BootRomComputedCrc;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x008: // W1C on HAD_PSM_RESTART | HAD_RUN | HAD_POR
                chipReset &= ~(value & 0x00110100U);
                break;
            case 0x010:
                BootRomStatus = value;
                break;
            case 0x014:
                BootRomComputedCrc = value;
                break;
            }
        }

        public void Reset()
        {
            // ARMv6-M PMSAv6 MPU resets to disabled on every system reset;
            // Stage 0 and Stage 1 re-apply MPU protection before handoff.
            mpuCtrl = 0U;
            mpuRnr = 0U;
            Array.Clear(mpuRbar, 0, mpuRbar.Length);
            Array.Clear(mpuRasr, 0, mpuRasr.Length);
        }

        private uint ReadNvicOrMpu(uint currentVal, long offset)
        {
            switch(offset)
            {
            case 0xD90: // MPU_TYPE (8 unified data/instruction regions on RP2040 Cortex-M0+)
                return 0x00000800U;
            case 0xD94: // MPU_CTRL
                return mpuCtrl;
            case 0xD98: // MPU_RNR
                return mpuRnr;
            case 0xD9C: // MPU_RBAR
                return mpuRbar[mpuRnr & 0x7U];
            case 0xDA0: // MPU_RASR
                return mpuRasr[mpuRnr & 0x7U];
            default:
                return currentVal;
            }
        }

        private uint WriteNvicOrMpu(uint value, long offset)
        {
            switch(offset)
            {
            case 0xD94: // MPU_CTRL
                mpuCtrl = value & 0x07U;
                break;
            case 0xD98: // MPU_RNR
                mpuRnr = value & 0x07U;
                break;
            case 0xD9C: // MPU_RBAR
                if((value & (1U << 4)) != 0U)
                {
                    mpuRnr = value & 0x07U;
                }
                mpuRbar[mpuRnr & 0x7U] = (value & 0xFFFFFF00U) | (mpuRnr & 0x07U);
                break;
            case 0xDA0: // MPU_RASR
                mpuRasr[mpuRnr & 0x7U] = value;
                break;
            }
            return value;
        }

        private const uint ChipResetHadPorBit = 0x00000100U;
        private const uint ChipResetHadPsmRestartBit = 0x00100000U;

        // Assembler-verified ARMv6-M Thumb RP2040 Mask-ROM at 0x00000000 (436 bytes):
        //   [0x000] MSP=0x20041F00, Reset=0x00000101, NMI/HardFault=0x000000F9
        //   [0x010] 'M','U',0x01,0x01 + ROM function/data/lookup pointers
        //   [0x040] ROM table ('IF', 'EX', 'FC') + [0x080] rom_table_lookup
        //   [0x100] _rom_reset: parks Core 1 via SIO->CPUID, enables SSI 03h XIP, copies
        //           256B from 0x10000000 to 0x20041F00, verifies non-reflected MPEG-2 CRC-32
        //           (poly=0x04C11DB7, init=0xFFFFFFFF, xorout=0) of [0..252] vs [252..256],
        //           wipes 0x20041F00 + halts in ROM on mismatch, or branches to boot2 in SRAM5!
        private static readonly uint[] BootRomWords = new uint[]
        {
            0x20041F00U, 0x00000101U, 0x000000F9U, 0x000000F9U, 0x0101554DU, 0x00600040U,
            0x00000081U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
            0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00A14649U, 0x00A35845U,
            0x00C14346U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
            0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
            0x00000000U, 0x00000000U, 0x2A008802U, 0x428AD003U, 0x3004D003U, 0x2000E7F8U,
            0x88404770U, 0x00004770U, 0x00000000U, 0x00000000U, 0x48384770U, 0x60812100U,
            0x61412104U, 0x60014936U, 0x60412100U, 0x49364A35U, 0x21015081U, 0x47706081U,
            0x21014834U, 0x60416001U, 0x00004770U, 0x00000000U, 0x00000000U, 0x00000000U,
            0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
            0x00000000U, 0x00000000U, 0xBF30B672U, 0x0000E7FDU, 0x4825B672U, 0x28006800U,
            0xF7FFD139U, 0xF7FFFFCAU, 0x4822FFD7U, 0x22404922U, 0x600B6803U, 0x31043004U,
            0xD1F93A01U, 0x21FC481EU, 0x43D22200U, 0x78044B1DU, 0x06243001U, 0x25084062U,
            0x2A000056U, 0x405EDA00U, 0x3D010032U, 0x3901D1F8U, 0x6804D1F1U, 0x616A4D16U,
            0xD10942A2U, 0x61294915U, 0x68014811U, 0x29200E09U, 0x3040D100U, 0x47003001U,
            0x61294911U, 0x2100480CU, 0x60012240U, 0x3A013004U, 0xBF30D1FBU, 0xBF20E7FDU,
            0x0000E7FDU, 0x18000000U, 0x001F0300U, 0x000000F4U, 0x03000218U, 0x14000000U,
            0xD0000000U, 0x10000000U, 0x20041F00U, 0x04C11DB7U, 0x40064000U, 0x600DC2C0U,
            0xBAD0C2C0U
        };

        private readonly IMachine machine;
        private readonly MappedMemory rom;
        private readonly Rp2040Watchdog watchdog;
        private readonly Rp2040SsiNor ssi;
        private readonly NVIC nvic0;
        private bool mpuHooksInstalled;
        private uint chipReset;

        private uint mpuCtrl;
        private uint mpuRnr;
        private readonly uint[] mpuRbar = new uint[8];
        private readonly uint[] mpuRasr = new uint[8];
    }

    public class Rp2040Sio : IDoubleWordPeripheral, IKnownSize
    {
        public Rp2040Sio(IMachine machine, CortexM cpu1 = null)
        {
            this.machine = machine;
            this.cpu1 = cpu1;
        }

        public long Size => 0x200;

        public uint ReadDoubleWord(long offset)
        {
            if(offset == 0x000) // CPUID
            {
                if(cpu1 != null && machine.SystemBus.TryGetCurrentCPU(out var currentCpu) && ReferenceEquals(currentCpu, cpu1))
                {
                    return 1U;
                }
                return 0U;
            }
            return 0U;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
        }

        public void Reset()
        {
        }

        private readonly IMachine machine;
        private readonly CortexM cpu1;
    }
}
