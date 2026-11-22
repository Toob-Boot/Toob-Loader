//
// Nordic nRF52840 SoC Hardware Overlay for Headless Renode 1.17.0 E2E Testing
//
// Models the nRF52840 peripherals not included in stock Renode nrf52840.repl:
//   - FICR       (0x10000000): Factory DEVICEID[0..1] & flash geometry registers
//   - UICR       (0x10001000): Non-volatile CUSTOMER[0..31] OTP/NOR registers (1->0)
//   - POWER/BPROT(0x40000400): Persistent RESETREAS & GPREGRET + volatile per-boot
//                              BPROT 4KB flash block write/erase protection
//   - NVMC       (0x4001E000): NOR 1->0 flash programming, ERASEPAGE, ERASEUICR,
//                              ICACHECNF, and hardware BPROT enforcement on flash!
//

using System;
using System.IO;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.Timers;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class Nrf52840Ficr : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x1000;

        public uint DeviceId0 { get; set; } = 0x01008452U;
        public uint DeviceId1 { get; set; } = 0xEFBEADDEU;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x010:
                return 0x1000U; // CODEPAGESIZE = 4096
            case 0x014:
                return 0x0100U; // CODESIZE = 256 pages (1 MB)
            case 0x060:
                return DeviceId0;
            case 0x064:
                return DeviceId1;
            case 0x0A0:
                return 0x00000001U;
            case 0x0A4:
                return DeviceId0;
            case 0x0A8:
                return DeviceId1;
            default:
                return 0xFFFFFFFFU;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            // FICR is read-only factory information ROM.
        }

        public void Reset()
        {
        }
    }

    public class Nrf52840PowerBprot : IDoubleWordPeripheral, IKnownSize, IGPIOReceiver
    {
        public Nrf52840PowerBprot(IMachine machine, NRF52840_Watchdog wdt = null)
        {
            this.machine = machine;
            if(wdt != null)
            {
                wdt.LimitReached += OnWatchdogBark;
            }
        }

        public long Size => 0x600;

        public uint ResetReas
        {
            get => resetReas;
            set => resetReas = value;
        }

        public uint BlockedOperations { get; internal set; }

        public bool IsBlockProtected(int blockIndex)
        {
            if(blockIndex < 0)
            {
                return false;
            }
            if(blockIndex < 32)
            {
                return ((bprotConfig0 >> blockIndex) & 1U) != 0U;
            }
            if(blockIndex < 64)
            {
                return ((bprotConfig1 >> (blockIndex - 32)) & 1U) != 0U;
            }
            if(blockIndex < 96)
            {
                return ((bprotConfig2 >> (blockIndex - 64)) & 1U) != 0U;
            }
            if(blockIndex < 128)
            {
                return ((bprotConfig3 >> (blockIndex - 96)) & 1U) != 0U;
            }
            return false;
        }

        public void OnGPIO(int number, bool value)
        {
            if(number == 0 && value)
            {
                resetReas |= ResetReasSreqBit;
                this.Log(LogLevel.Info, "SYSRESETREQ latched RESETREAS=0x{0:X8}; requesting warm reset.", resetReas);
                machine.RequestReset();
            }
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x000: // POWER->RESETREAS (0x40000400)
                return resetReas;
            case 0x11C: // POWER->GPREGRET  (0x4000051C)
                return gpRegRet;
            case 0x120: // POWER->GPREGRET2 (0x40000520)
                return gpRegRet2;
            case 0x200: // BPROT->CONFIG0   (0x40000600)
                return bprotConfig0;
            case 0x204: // BPROT->CONFIG1   (0x40000604)
                return bprotConfig1;
            case 0x208: // BPROT->DISABLEINDEBUG (0x40000608)
                return bprotDisableInDebug;
            case 0x210: // BPROT->CONFIG2   (0x40000610)
                return bprotConfig2;
            case 0x214: // BPROT->CONFIG3   (0x40000614)
                return bprotConfig3;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x000: // Write-1-to-clear RESETREAS
                resetReas &= ~value;
                break;
            case 0x11C:
                gpRegRet = value & 0xFFU;
                break;
            case 0x120:
                gpRegRet2 = value & 0xFFU;
                break;
            case 0x200: // Sticky 1-bits until next system reset
                bprotConfig0 |= value;
                break;
            case 0x204:
                bprotConfig1 |= value;
                break;
            case 0x208:
                bprotDisableInDebug = value & 1U;
                break;
            case 0x210:
                bprotConfig2 |= value;
                break;
            case 0x214:
                bprotConfig3 |= value;
                break;
            }
        }

        public void Reset()
        {
            // BPROT clears on every system reset; RESETREAS and GPREGRET persist across warm resets!
            bprotConfig0 = 0U;
            bprotConfig1 = 0U;
            bprotConfig2 = 0U;
            bprotConfig3 = 0U;
            bprotDisableInDebug = 0U;
        }

        private void OnWatchdogBark()
        {
            resetReas |= ResetReasDogBit;
            this.Log(LogLevel.Info, "Watchdog bark latched RESETREAS=0x{0:X8}; requesting warm reset.", resetReas);
            machine.RequestReset();
        }

        private const uint ResetReasDogBit = 0x02U;
        private const uint ResetReasSreqBit = 0x04U;

        private readonly IMachine machine;
        private uint resetReas;
        private uint gpRegRet;
        private uint gpRegRet2;
        private uint bprotConfig0;
        private uint bprotConfig1;
        private uint bprotConfig2;
        private uint bprotConfig3;
        private uint bprotDisableInDebug;
    }

    public class Nrf52840Uicr : IDoubleWordPeripheral, IKnownSize
    {
        public Nrf52840Uicr()
        {
            EraseAll();
        }

        public long Size => 0x1000;

        internal uint NvmcConfig { get; set; }

        public void EraseAll()
        {
            for(int i = 0; i < words.Length; i++)
            {
                words[i] = 0xFFFFFFFFU;
            }
        }

        public void LoadBinary(string path)
        {
            byte[] raw = File.ReadAllBytes(path);
            EraseAll();
            int len = Math.Min(raw.Length, words.Length * 4);
            for(int i = 0; i + 4 <= len; i += 4)
            {
                uint w = (uint)raw[i]
                       | ((uint)raw[i + 1] << 8)
                       | ((uint)raw[i + 2] << 16)
                       | ((uint)raw[i + 3] << 24);
                words[i / 4] = w;
            }
        }

        public void SaveBinary(string path)
        {
            byte[] raw = new byte[words.Length * 4];
            for(int i = 0; i < words.Length; i++)
            {
                uint w = words[i];
                raw[i * 4 + 0] = (byte)(w & 0xFFU);
                raw[i * 4 + 1] = (byte)((w >> 8) & 0xFFU);
                raw[i * 4 + 2] = (byte)((w >> 16) & 0xFFU);
                raw[i * 4 + 3] = (byte)((w >> 24) & 0xFFU);
            }
            File.WriteAllBytes(path, raw);
        }

        public uint ReadDoubleWord(long offset)
        {
            int idx = (int)((offset >> 2) & 0x3FFL);
            return words[idx];
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            if(NvmcConfig != 1U)
            {
                this.Log(LogLevel.Warning, "Blocked UICR write at +0x{0:X3} while NVMC.CONFIG={1}", offset, NvmcConfig);
                return;
            }
            int idx = (int)((offset >> 2) & 0x3FFL);
            words[idx] &= value;
        }

        public void Reset()
        {
            NvmcConfig = 0U;
        }

        private readonly uint[] words = new uint[1024];
    }

    public class Nrf52840Nvmc : IDoubleWordPeripheral, IKnownSize
    {
        public Nrf52840Nvmc(IMachine machine, MappedMemory flash, Nrf52840Uicr uicr, Nrf52840PowerBprot powerBprot)
        {
            this.machine = machine;
            this.flash = flash;
            this.uicr = uicr;
            this.powerBprot = powerBprot;
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
                sysbus.SetPageAccessViaIo(page);
            }
        }

        public long Size => 0x1000;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x400: // READY
            case 0x408: // READYNEXT
                return 1U;
            case 0x504: // CONFIG
                return config;
            case 0x540: // ICACHECNF
                return icacheCnf;
            default:
                return 0U;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
            case 0x504: // CONFIG (0=Ren, 1=Wen, 2=Een)
                config = value & 0x3U;
                if(uicr != null)
                {
                    uicr.NvmcConfig = config;
                }
                break;
            case 0x508: // ERASEPAGE
            case 0x510: // ERASEPCR0
                HandleErasePage(value);
                break;
            case 0x50C: // ERASEALL
                if(config == ModeEraseEnable)
                {
                    int totalBlocks = (int)(flash.Size / (long)PageSizeBytes);
                    for(int blk = 0; blk < totalBlocks; blk++)
                    {
                        if(powerBprot == null || !powerBprot.IsBlockProtected(blk))
                        {
                            flash.SetRange((long)blk * (long)PageSizeBytes, (long)PageSizeBytes, 0xFF);
                        }
                    }
                    uicr?.EraseAll();
                }
                break;
            case 0x514: // ERASEUICR
                if(config == ModeEraseEnable)
                {
                    uicr?.EraseAll();
                }
                break;
            case 0x540: // ICACHECNF
                icacheCnf = value;
                break;
            }
        }

        public void Reset()
        {
            config = ModeReadOnly;
            icacheCnf = 0U;
            if(uicr != null)
            {
                uicr.NvmcConfig = ModeReadOnly;
            }
            if(hooksInstalled)
            {
                ApplyPageAccessViaIo();
            }
        }

        private void HandleErasePage(uint pageAddress)
        {
            if(config != ModeEraseEnable)
            {
                this.Log(LogLevel.Warning, "Ignored ERASEPAGE(0x{0:X8}) while NVMC.CONFIG={1}", pageAddress, config);
                return;
            }
            if(pageAddress >= (uint)flash.Size)
            {
                return;
            }
            uint alignedPage = pageAddress & ~(uint)(PageSizeBytes - 1UL);
            int block = (int)(alignedPage / (uint)PageSizeBytes);
            if(powerBprot != null && powerBprot.IsBlockProtected(block))
            {
                powerBprot.BlockedOperations++;
                this.Log(LogLevel.Warning, "BPROT blocked ERASEPAGE on protected block {0} (0x{1:X8})", block, alignedPage);
                return;
            }
            flash.SetRange(alignedPage, (long)PageSizeBytes, 0xFF);
        }

        private uint FilterWriteDoubleWord(uint value, long offset)
        {
            uint existing = flash.ReadDoubleWord(offset);
            if(!CanProgramOffset(offset))
            {
                return existing;
            }
            return existing & value;
        }

        private ushort FilterWriteWord(ushort value, long offset)
        {
            ushort existing = flash.ReadWord(offset);
            if(!CanProgramOffset(offset))
            {
                return existing;
            }
            return (ushort)(existing & value);
        }

        private byte FilterWriteByte(byte value, long offset)
        {
            byte existing = flash.ReadByte(offset);
            if(!CanProgramOffset(offset))
            {
                return existing;
            }
            return (byte)(existing & value);
        }

        private bool CanProgramOffset(long offset)
        {
            if(config != ModeWriteEnable)
            {
                return false;
            }
            int block = (int)(offset / (long)PageSizeBytes);
            if(powerBprot != null && powerBprot.IsBlockProtected(block))
            {
                powerBprot.BlockedOperations++;
                this.Log(LogLevel.Warning, "BPROT blocked flash write at 0x{0:X8} (block {1})", offset, block);
                return false;
            }
            return true;
        }

        private const ulong PageSizeBytes = 0x1000UL;
        private const uint ModeReadOnly = 0U;
        private const uint ModeWriteEnable = 1U;
        private const uint ModeEraseEnable = 2U;

        private readonly IMachine machine;
        private readonly MappedMemory flash;
        private readonly Nrf52840Uicr uicr;
        private readonly Nrf52840PowerBprot powerBprot;
        private bool hooksInstalled;
        private uint config;
        private uint icacheCnf;
    }
}
