'use client';

/**
 * Toob-Boot Bootloader & Flash Swap Simulation
 *
 * This component visualizes the transaction flow of a secure firmware update.
 *
 * Physical Memory Architecture:
 * 1. APP-SLOT (Slot A): Active firmware executing XIP (Execute-in-Place) at 0x0800_8000.
 * 2. STAGING-SLOT (Slot B): Inactive staging area where updates are downloaded at 0x0806_0000.
 * 3. SCRATCH-SLOT: Dedicated partition used for delta patch reconstruction (SDVM) at 0x0804_0000
 *    and as a single-sector temporary buffer during swapping.
 * 4. WAL-JOURNAL: Completely separate flash partition (typically 4 sectors) at 0x080C_0000.
 *    Used to log intents and block swap checkpoints before physical writes.
 *
 * Power-Loss Swapping Logic (3-Way Rotation):
 * For each sector k:
 * - A WAL checkpoint is written to the WAL-JOURNAL partition (offset = k * sector_size).
 * - Phase A: App sector k is copied into the Scratch sector.
 * - Phase B: Staging sector k is copied into the App sector k.
 * - Phase C: Scratch sector is copied into the Staging sector k (backup).
 * If power is cut at any point, the data is preserved in at least one slot. On reboot,
 * the bootloader reads the WAL, detects the checkpoint, and resumes the swap from k.
 */

import { useState, useEffect, useRef } from 'react';
import styles from './BootSimulation.module.css';

interface LogLine {
  html: string;
}

interface Transfer {
  id: string;
  type: 'dl' | 'stgToScr' | 'appToScr' | 'swap' | 'rollback' | 'appToStg' | 'walWrite';
  index: number;
  step: number; // 0 = start, 1 = end/moving
}

export default function BootSimulation() {
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [flicker, setFlicker] = useState(false);
  const [walPulsing, setWalPulsing] = useState(false);
  const [tmrQuorum, setTmrQuorum] = useState(3);
  const [bootSuccess, setBootSuccess] = useState(false);
  const [cutRequested, setCutRequested] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  
  // Flash states (16 sectors)
  const [appSectors, setAppSectors] = useState<string[]>(Array(16).fill('blkOld'));
  const [stagingSectors, setStagingSectors] = useState<string[]>(Array(16).fill('blkEmpty'));
  const [scratchSectors, setScratchSectors] = useState<string[]>(Array(16).fill('blkEmpty'));
  const [walSectors, setWalSectors] = useState<string[]>(Array(4).fill('blkEmpty'));
  const [walMeta, setWalMeta] = useState({
    seq: 42,
    intent: 'TOOB_WAL_INTENT_NONE',
    details: 'System Bereit',
    erase: 12,
    crc: '0x00000000',
  });
  const [trackedStaging, setTrackedStaging] = useState<boolean[]>(Array(16).fill(false));
  const [trackedScratch, setTrackedScratch] = useState<boolean[]>(Array(16).fill(false));
  const [trackedApp, setTrackedApp] = useState<boolean[]>(Array(16).fill(false));
  const [activeWalSec, setActiveWalSec] = useState<number | null>(null);
  
  // Ghost transfers
  const [activeTransfers, setActiveTransfers] = useState<Transfer[]>([]);
  const [tornBlockIndex, setTornBlockIndex] = useState<number | null>(null);
  const [tornPct, setTornPct] = useState<number>(0);

  // Blackout Overlay State
  const [isBlackout, setIsBlackout] = useState(false);

  // Row Swap Animation States (Deprecated for granular swap, kept for dynamic offset compatibility)
  const [rowSwapOffset, setRowSwapOffset] = useState(0);
  const [isRowSwapped, setIsRowSwapped] = useState(false);
  const [frozenSwap, setFrozenSwap] = useState(false);

  // Refs for dynamic DOM alignment measurement
  const stagingRef = useRef<HTMLDivElement>(null);
  const scratchRef = useRef<HTMLDivElement>(null);
  const appRef = useRef<HTMLDivElement>(null);
  const walRef = useRef<HTMLDivElement>(null);
  const slotsContainerRef = useRef<HTMLDivElement>(null);

  // Engine refs
  const activeRef = useRef(true);
  const cutRequestedRef = useRef(false);

  // Modified sector indices
  const modifiedIndices = [2, 5, 8, 11, 14];

  // Helper utils
  const hex = (i: number) => "0x0800_" + (0x8000 + i * 0x800).toString(16).toUpperCase().padStart(4, "0");
  const ts = () => `<span class="${styles.logT}">› </span> `;

  const addLog = (html: string) => {
    setLogs(prev => {
      const next = [...prev, { html }];
      if (next.length > 7) {
        return next.slice(next.length - 7);
      }
      return next;
    });
  };

  const walPulse = () => {
    setWalPulsing(true);
    setTimeout(() => setWalPulsing(false), 300);
  };

  const handleCutClick = () => {
    cutRequestedRef.current = true;
    setCutRequested(true);
  };

  // Helper to dynamically calculate block left and width relative to container
  const getBlockLeft = (rowName: 'staging' | 'scratch' | 'app', index: number) => {
    const container = slotsContainerRef.current;
    let target = null;
    if (rowName === 'staging') target = stagingRef.current;
    else if (rowName === 'scratch') target = scratchRef.current;
    else if (rowName === 'app') target = appRef.current;
    
    if (!container || !target) return 0;
    
    const cRect = container.getBoundingClientRect();
    const blocks = target.querySelectorAll(`.${styles.blk}`);
    if (!blocks || !blocks[index]) return 0;
    
    const bRect = blocks[index].getBoundingClientRect();
    return bRect.left - cRect.left;
  };

  const getBlockWidth = (rowName: 'staging' | 'scratch' | 'app', index: number) => {
    let target = null;
    if (rowName === 'staging') target = stagingRef.current;
    else if (rowName === 'scratch') target = scratchRef.current;
    else target = appRef.current;
    
    if (!target) return 0;
    const blocks = target.querySelectorAll(`.${styles.blk}`);
    if (!blocks || !blocks[index]) return 0;
    return blocks[index].getBoundingClientRect().width;
  };

  const getWalSectorLeft = (index: number) => {
    const container = slotsContainerRef.current;
    const target = walRef.current;
    if (!container || !target) return 0;
    
    const cRect = container.getBoundingClientRect();
    const blocks = target.querySelectorAll(`.${styles.blkWal}`);
    if (!blocks || !blocks[index]) return 0;
    
    const bRect = blocks[index].getBoundingClientRect();
    return bRect.left - cRect.left;
  };

  const getWalSectorWidth = (index: number) => {
    const target = walRef.current;
    if (!target) return 0;
    const blocks = target.querySelectorAll(`.${styles.blkWal}`);
    if (!blocks || !blocks[index]) return 0;
    return blocks[index].getBoundingClientRect().width;
  };

  const getWalRowTop = () => {
    const container = slotsContainerRef.current;
    const target = walRef.current;
    if (!container || !target) return 0;
    
    const cRect = container.getBoundingClientRect();
    const blockRow = target.querySelector(`.${styles.blocksWal}`);
    if (!blockRow) return 0;
    
    const tRect = blockRow.getBoundingClientRect();
    return tRect.top - cRect.top;
  };

  const getTransferLeft = (type: string, index: number, step: number) => {
    if (type === 'walWrite') {
      return step === 0 ? getWalSectorLeft(Math.floor(index / 4)) : getBlockLeft('app', index);
    }
    if (type === 'dl') return getBlockLeft('staging', index);
    if (type === 'stgToScr') return getBlockLeft('scratch', index);
    if (type === 'appToScr') return getBlockLeft('app', index); 
    if (type === 'swap') return getBlockLeft('scratch', index); 
    if (type === 'rollback') return getBlockLeft('scratch', index);
    if (type === 'appToStg') return getBlockLeft('app', index);
    return 0;
  };

  const getTransferWidth = (type: string, index: number, step: number) => {
    if (type === 'walWrite') {
      return step === 0 ? getWalSectorWidth(Math.floor(index / 4)) : getBlockWidth('app', index);
    }
    if (type === 'dl') return getBlockWidth('staging', index);
    if (type === 'appToScr') return getBlockWidth('app', index);
    if (type === 'appToStg') return getBlockWidth('app', index);
    return getBlockWidth('scratch', index);
  };

  const getRowTop = (rowName: 'staging' | 'scratch' | 'app') => {
    const container = slotsContainerRef.current;
    let target = null;
    if (rowName === 'staging') target = stagingRef.current;
    else if (rowName === 'scratch') target = scratchRef.current;
    else if (rowName === 'app') target = appRef.current;
    
    if (!container || !target) return 0;
    
    const cRect = container.getBoundingClientRect();
    const blockRow = target.querySelector(`.${styles.blocks}`);
    if (!blockRow) return 0;
    
    const tRect = blockRow.getBoundingClientRect();
    return tRect.top - cRect.top;
  };


  const getTransferTop = (type: string, step: number) => {
    if (type === 'walWrite') {
      return step === 0 ? getWalRowTop() : getRowTop('app');
    }
    if (type === 'dl') {
      return step === 0 ? getRowTop('staging') - 26 : getRowTop('staging');
    }
    if (type === 'stgToScr') {
      return step === 0 ? getRowTop('staging') : getRowTop('scratch');
    }
    if (type === 'appToScr') {
      return step === 0 ? getRowTop('app') : getRowTop('scratch');
    }
    if (type === 'swap') {
      return step === 0 ? getRowTop('scratch') : getRowTop('app');
    }
    if (type === 'rollback') {
      return step === 0 ? getRowTop('scratch') : getRowTop('staging');
    }
    if (type === 'appToStg') {
      return step === 0 ? getRowTop('app') : getRowTop('staging');
    }
    return 0;
  };

  useEffect(() => {
    activeRef.current = true;
    let loopTimeout: NodeJS.Timeout | null = null;

    const sleep = (ms: number) => new Promise<void>(resolve => {
      const startTime = Date.now();
      const interval = setInterval(() => {
        if (cutRequestedRef.current || Date.now() - startTime >= ms || !activeRef.current) {
          clearInterval(interval);
          resolve();
        }
      }, 10);
    });

    const runRollingCheck = async (row: 'staging' | 'scratch' | 'app', limit = 16) => {
      for (let j = 0; j < limit; j++) {
        if (!activeRef.current) return;
        
        // Skip checking empty sectors in Staging to only sweep written delta patch blocks
        if (row === 'staging' && !modifiedIndices.includes(j)) {
          continue;
        }

        if (row === 'staging') {
          setStagingSectors(prev => {
            const next = [...prev];
            next[j] = 'blkSkip';
            return next;
          });
        } else if (row === 'scratch') {
          setScratchSectors(prev => {
            const next = [...prev];
            next[j] = 'blkSkip';
            return next;
          });
        } else {
          setAppSectors(prev => {
            const next = [...prev];
            next[j] = 'blkSkip';
            return next;
          });
        }
        await sleep(35);
      }
      await sleep(150);
      if (!activeRef.current) return;

      if (row === 'staging') {
        setStagingSectors(prev => prev.map((s, idx) => idx < limit && s === 'blkSkip' ? (modifiedIndices.includes(idx) ? 'blkPatch' : 'blkEmpty') : s));
      } else if (row === 'scratch') {
        setScratchSectors(prev => prev.map((s, idx) => idx < limit && s === 'blkSkip' ? (modifiedIndices.includes(idx) ? 'blkFull' : 'blkScratch') : s));
      } else {
        setAppSectors(prev => prev.map((s, idx) => idx < limit && s === 'blkSkip' ? 'blkFull' : s));
      }
    };

    const triggerTransfer = async (type: 'dl' | 'stgToScr' | 'appToScr' | 'swap' | 'rollback' | 'appToStg', index: number, delay = 240) => {
      const id = Math.random().toString(36).substring(2, 9);
      const t: Transfer = { id, type, index, step: 0 };
      
      // Step 0: Render start position
      setActiveTransfers(prev => [...prev, t]);
      
      // Step 1: Animate to end position in next tick
      await sleep(15);
      setActiveTransfers(prev => prev.map(x => x.id === id ? { ...x, step: 1 } : x));
      
      // Wait for transition duration
      await sleep(delay);
      
      // Step 2: Remove from state
      setActiveTransfers(prev => prev.filter(x => x.id !== id));
    };

    const triggerPowerCut = async (iBlock: number, pct: number, onScratch = false) => {
      cutRequestedRef.current = false;
      
      // Volatile RAM wiped on power loss
      setActiveTransfers([]);
      
      // Trigger true blackout overlay
      setIsBlackout(true);

      // Visual torn block gradient
      if (pct > 0) {
        setTornBlockIndex(iBlock);
        setTornPct(pct);
        if (onScratch) {
          setScratchSectors(prev => {
            const next = [...prev];
            next[iBlock] = 'blkTorn';
            return next;
          });
        } else {
          setAppSectors(prev => {
            const next = [...prev];
            next[iBlock] = 'blkTorn';
            return next;
          });
        }
      }

      addLog(`power lost · sector ${iBlock + 1}`);
      
      // Keep in blackout for exactly 200ms (1/3 of 600ms)
      await new Promise<void>(resolve => {
        loopTimeout = setTimeout(resolve, 200);
      });
      setIsBlackout(false);
      
      setCutRequested(false);
      if (!activeRef.current) return 'abort';
      return 'restored';
    };

    const runSimulationLoop = async () => {
      let dlCut = false;
      let reconCut = false;
      let swapCut = false;
      let swapIndex = 0;

      while (activeRef.current) {
        // RESET INITIAL STATE
        setLogs([]);
        setActiveTransfers([]);
        setBootSuccess(false);
        setTmrQuorum(3);

        if (dlCut) {
          // Erase the incomplete Staging sectors (red flash & fade)
          setStagingSectors(prev => prev.map(s => s === 'blkPatch' ? 'blkErase' : s));
          setScratchSectors(Array(16).fill('blkEmpty'));
          setAppSectors(Array(16).fill('blkOld'));
          setWalSectors(Array(4).fill('blkEmpty'));
          dlCut = false;
        } else if (reconCut) {
          // Keep Staging complete, but Erase the incomplete Scratch sectors (red flash & fade)
          setStagingSectors(prev => prev.map((s, idx) => modifiedIndices.includes(idx) ? 'blkPatch' : 'blkEmpty'));
          setScratchSectors(prev => prev.map(s => s !== 'blkEmpty' ? 'blkErase' : s));
          setAppSectors(Array(16).fill('blkOld'));
          setWalSectors(['blkWal', 'blkEmpty', 'blkEmpty', 'blkEmpty']);
          reconCut = false;
        } else if (swapCut) {
          const activeWalSecVal = Math.floor(swapIndex / 4);
          setWalSectors(prev => {
            const next = Array(4).fill('blkEmpty');
            for (let i = 0; i < activeWalSecVal; i++) {
              next[i] = 'blkWal';
            }
            next[activeWalSecVal] = 'blkWalActive';
            return next;
          });
          swapCut = false;
        } else {
          setAppSectors(Array(16).fill('blkOld'));
          setStagingSectors(Array(16).fill('blkEmpty'));
          setScratchSectors(Array(16).fill('blkEmpty'));
          setWalSectors(Array(4).fill('blkEmpty'));
        }
        cutRequestedRef.current = false;
        setCutRequested(false);
        setIsUpdating(false);
        setTornBlockIndex(null);
        setTornPct(0);
        setIsRowSwapped(false);
        setRowSwapOffset(0);
        setFrozenSwap(false);
        setTrackedStaging(Array(16).fill(false));
        setTrackedScratch(Array(16).fill(false));
        setTrackedApp(Array(16).fill(false));
        setActiveWalSec(null);
        setWalMeta({
          seq: 42,
          intent: 'TOOB_WAL_INTENT_NONE',
          details: 'System Bereit',
          erase: 12,
          crc: '0x00000000',
        });  
        await sleep(1500);
        if (!activeRef.current) return;

        addLog(ts() + `reset and reboot`);
        setIsUpdating(true);
        await sleep(1200);

        // ==========================================
        // 1. DOWNLOAD
        // ==========================================
        addLog(ts() + `load delta-patches`);
        // Log WAL Update pending
        setActiveWalSec(0);
        setWalSectors(prev => {
          const next = [...prev];
          next[0] = 'blkWalActive';
          return next;
        });
        setTimeout(() => {
          setWalSectors(prev => {
            const next = [...prev];
            next[0] = 'blkEmpty';
            return next;
          });
        }, 300);
        await sleep(400);

        dlCut = false;
        for (let k = 0; k < 16; k++) {
          if (cutRequestedRef.current) {
            dlCut = true;
            await triggerPowerCut(k, 0);
            break;
          }

          if (modifiedIndices.includes(k)) {
            // Highlight only the active downloading sector in Staging
            setTrackedStaging(prev => {
              const next = Array(16).fill(false);
              next[k] = true;
              return next;
            });

            await triggerTransfer('dl', k, 240);
            setStagingSectors(prev => {
              const next = [...prev];
              next[k] = 'blkPatch';
              return next;
            });
            await sleep(120);
          } else {
            // Clear outline highlights during skipped sectors
            setTrackedStaging(Array(16).fill(false));
            await sleep(40);
          }
          if (!activeRef.current) return;
        }

        // Clear staging outlines after download finishes
        setTrackedStaging(Array(16).fill(false));

        if (dlCut) {
          setActiveWalSec(null);
          addLog(ts() + `error: download incomplete`);
          await sleep(650);
          addLog(ts() + `boot app v1 safe`);
          await sleep(4000);
          continue; // reset the loop
        }

        // Staging signature and CRC check
        addLog(ts() + `verify delta-patches`);
        addLog(ts() + `write update-flag`);
        await sleep(400);

        // ==========================================
        // 2. MAILBOX FLAG & REBOOT
        // ==========================================
        addLog(ts() + `reboot sequence`);
        await sleep(800);
        
        // Reboot sequence
        addLog(ts() + `reset and restart`);
        setAppSectors(Array(16).fill('blkEmpty'));
        await sleep(600);
        setAppSectors(Array(16).fill('blkOld'));
        await sleep(800);

        // ==========================================
        // 3. SECURITY GATE
        // ==========================================
        addLog(ts() + `signatures valid`);
        walPulse();
        await sleep(1000);

        // ==========================================
        // 4. DELTA RECONSTRUCT (Merging)
        // ==========================================
        addLog(ts() + `reconstruct image`);
        // Log WAL Begin
        setActiveWalSec(0);
        setWalSectors(prev => {
          const next = [...prev];
          next[0] = 'blkWalActive';
          return next;
        });
        setTimeout(() => {
          setWalSectors(prev => {
            const next = [...prev];
            next[0] = 'blkEmpty';
            return next;
          });
        }, 300);
        await sleep(400);

        reconCut = false;
        for (let k = 0; k < 16; k++) {
          if (cutRequestedRef.current) {
            reconCut = true;
            await triggerPowerCut(k, 0);
            break;
          }

          // Track the active merge column in App and Scratch slots
          setTrackedScratch(prev => {
            const next = Array(16).fill(false);
            next[k] = true;
            return next;
          });
          setTrackedApp(prev => {
            const next = Array(16).fill(false);
            next[k] = true;
            return next;
          });
          if (modifiedIndices.includes(k)) {
            setTrackedStaging(prev => {
              const next = Array(16).fill(false);
              next[k] = true;
              return next;
            });
          }

          setWalMeta({
            seq: 44,
            intent: 'TOOB_WAL_INTENT_TXN_BEGIN',
            details: `Reconstruct: sector ${k+1}/16`,
            erase: 12,
            crc: `0xFA3C9D${k.toString(16).toUpperCase()}E`,
          });

          const promises: Promise<void>[] = [];
          promises.push(triggerTransfer('appToScr', k, 240));
          if (modifiedIndices.includes(k)) {
            promises.push(triggerTransfer('stgToScr', k, 240));
          }
          await Promise.all(promises);
          
          setScratchSectors(prev => {
            const next = [...prev];
            next[k] = modifiedIndices.includes(k) ? 'blkFull' : 'blkScratch';
            return next;
          });
          await sleep(100);
          if (!activeRef.current) return;
        }

        setTrackedScratch(Array(16).fill(false));
        setTrackedApp(Array(16).fill(false));
        setTrackedStaging(Array(16).fill(false));
        setActiveWalSec(null);

        if (reconCut) {
          addLog(ts() + `error: scratch invalid`);
          await sleep(650);
          addLog(ts() + `boot app v1 safe`);
          await sleep(4000);
          continue; // reset the loop
        }

        // Scratch image verification check
        addLog(ts() + `verify scratch integrity`);
        await runRollingCheck('scratch', 16);
        await sleep(800);

        // ==========================================
        // 5. SECTOR SWAP (Granular Sector-by-Sector Swap)
        // ==========================================
        addLog(ts() + `swap sectors`);
        await sleep(400);

        while (swapIndex < 16) {
          swapCut = false;

          for (let k = swapIndex; k < 16; k++) {
            if (cutRequestedRef.current) {
              swapCut = true;
              swapIndex = k;
              break;
            }

            const activeWalSecVal = Math.floor(k / 4);
            const seqId = k >= 8 ? 46 : 45;
            const eraseCount = k >= 8 ? 13 : 12;

            setWalMeta({
              seq: seqId,
              intent: 'TOOB_WAL_INTENT_TXN_BEGIN',
              details: `Swap: sector ${k+1}/16`,
              erase: eraseCount,
              crc: `0x7B8C9D${k.toString(16).toUpperCase()}A`,
            });

            // Set current column k as tracked under WAL checkpoint
            setTrackedScratch(prev => {
              const next = Array(16).fill(false);
              next[k] = true;
              return next;
            });
            setTrackedApp(prev => {
              const next = Array(16).fill(false);
              next[k] = true;
              return next;
            });
            setTrackedStaging(prev => {
              const next = Array(16).fill(false);
              next[k] = true;
              return next;
            });

            // Set active WAL sector for outlining & circular progress representation
            setActiveWalSec(activeWalSecVal);
            setWalSectors(prev => {
              const next = Array(4).fill('blkEmpty');
              for (let i = 0; i < activeWalSecVal; i++) {
                next[i] = 'blkWal';
              }
              next[activeWalSecVal] = 'blkWalActive';
              return next;
            });

            // 1. Write WAL checkpoint
            addLog(ts() + `wal: checkpoint sector ${k+1}`);
            await triggerTransfer('walWrite', k, 260);

            // Phase A: App -> Staging (Backup Old Sektor)
            if (cutRequestedRef.current) { swapCut = true; swapIndex = k; break; }
            setStagingSectors(prev => {
              const next = [...prev];
              next[k] = 'blkErase'; // Staging sector erased before write
              return next;
            });
            await sleep(150);
            if (cutRequestedRef.current) { swapCut = true; swapIndex = k; break; }

            await triggerTransfer('appToStg', k, 250);
            if (cutRequestedRef.current) { swapCut = true; swapIndex = k; break; }

            setStagingSectors(prev => {
              const next = [...prev];
              next[k] = 'blkOld'; // written backup
              return next;
            });
            await sleep(100);
            if (cutRequestedRef.current) { swapCut = true; swapIndex = k; break; }

            // Erase the source App sector now that the backup is safely written
            setAppSectors(prev => {
              const next = [...prev];
              next[k] = 'blkErase'; // App sector erased
              return next;
            });
            await sleep(150);

            // Phase B: Scratch -> App (new data to App)
            if (cutRequestedRef.current) { swapCut = true; swapIndex = k; break; }
            await triggerTransfer('swap', k, 250);
            setAppSectors(prev => {
              const next = [...prev];
              next[k] = 'blkFull'; // new firmware block in App
              return next;
            });
            setScratchSectors(prev => {
              const next = [...prev];
              next[k] = 'blkErase'; // scratch sector cleared (erased)
              return next;
            });
            await sleep(250);

            if (!activeRef.current) return;
            if (cutRequestedRef.current) { swapCut = true; swapIndex = k; break; }

            // Increment swapIndex on successful sector swap completion
            swapIndex = k + 1;
          }

          if (swapCut) {
            const activeWalSecVal = Math.floor(swapIndex / 4);
            const seqId = swapIndex >= 8 ? 46 : 45;
            const eraseCount = swapIndex >= 8 ? 13 : 12;

            // Trigger power cut visual on App sector at swapIndex
            const r = await triggerPowerCut(swapIndex, 45);
            if (r === 'abort') return;

            // Freeze the WAL tracked outline on the failed swap Index column!
            setTrackedScratch(prev => {
              const next = Array(16).fill(false);
              next[swapIndex] = true;
              return next;
            });
            setTrackedApp(prev => {
              const next = Array(16).fill(false);
              next[swapIndex] = true;
              return next;
            });
            setTrackedStaging(prev => {
              const next = Array(16).fill(false);
              next[swapIndex] = true;
              return next;
            });

            setWalMeta({
              seq: 0,
              intent: 'TOOB_WAL_INTENT_NONE',
              details: 'System crashed. Resetting...',
              erase: 0,
              crc: '—',
            });

            // --- RECOVERY BOOT SEQUENCE ---
            addLog(ts() + `reboot sequence`);
            await sleep(600);

            addLog(ts() + `verify bootloader status`);
            
            // Set active WAL sector for outlining & recover states
            setActiveWalSec(activeWalSecVal);
            setWalSectors(prev => {
              const next = Array(4).fill('blkEmpty');
              for (let i = 0; i < activeWalSecVal; i++) {
                next[i] = 'blkWal';
              }
              next[activeWalSecVal] = 'blkWalActive';
              return next;
            });

            setWalMeta({
              seq: seqId,
              intent: 'TOOB_WAL_INTENT_TXN_BEGIN',
              details: 'scanning sectors...',
              erase: eraseCount,
              crc: 'Calculating...',
            });
            await sleep(600);

            // Simulate TMR corruption detection and auto-healing
            addLog(ts() + `tmr error: healing sector`);
            setTmrQuorum(2);
            await sleep(550);
            setTmrQuorum(3);
            addLog(ts() + `tmr: healing complete`);
            await sleep(400);

            addLog(ts() + `wal: checkpoint found`);
            
            await triggerTransfer('walWrite', swapIndex, 300);

            setWalMeta({
              seq: seqId,
              intent: 'TOOB_WAL_INTENT_TXN_BEGIN',
              details: `Resume: sector ${swapIndex + 1}/16`,
              erase: eraseCount,
              crc: `0x7B8C9D${swapIndex.toString(16).toUpperCase()}A`,
            });
            await sleep(400);

            // Cascade skip flash on first swapIndex sectors of appSectors
            for (let j = 0; j < swapIndex; j++) {
              setAppSectors(prev => {
                const next = [...prev];
                next[j] = 'blkSkip';
                return next;
              });
              await sleep(45);
            }
            await sleep(300);

            // Restore app sectors to full
            setAppSectors(prev => {
              const next = [...prev];
              for (let j = 0; j < swapIndex; j++) {
                next[j] = 'blkFull';
              }
              return next;
            });

            addLog(ts() + `sectors 1-${swapIndex} skipped`);
            await sleep(650);
            addLog(ts() + `resume swap`);

            setTornBlockIndex(null);
            setTornPct(0);
            await sleep(400);
          }
        }

        // --- Transition Lock and State Commit Swap ---
        setTrackedScratch(Array(16).fill(false));
        setTrackedApp(Array(16).fill(false));
        setTrackedStaging(Array(16).fill(false));
        setFrozenSwap(true);
        setIsRowSwapped(false);
        setAppSectors(Array(16).fill('blkFull')); // App gets v2 (green/white)
        setScratchSectors(Array(16).fill('blkEmpty')); // Scratch cleared
        setWalMeta({
          seq: 47,
          intent: 'TOOB_WAL_INTENT_TXN_COMMIT',
          details: 'Warte auf Boot...',
          erase: 12,
          crc: '0x9D8E7C6B',
        });
        setWalSectors(['blkWal', 'blkWal', 'blkEmpty', 'blkEmpty']);
        await sleep(50);
        setFrozenSwap(false);

        setIsUpdating(false);
        await sleep(800);

        // ==========================================
        // 6. TENTATIVE BOOT & CONFIRM
        // ==========================================
        addLog(ts() + `trial-boot: app v2`);

        setWalMeta({
          seq: 47,
          intent: 'TOOB_WAL_INTENT_TXN_COMMIT',
          details: 'Bootet (Trial-Phase)...',
          erase: 12,
          crc: '0x9D8E7C6B',
        });
        await sleep(1500);

        // Success Confirm
        addLog(ts() + `confirm: trial-verification`);
        await sleep(600);
        
        // Self-test and signature verification on new App slot
        addLog(ts() + `verify app v2`);
        await runRollingCheck('app', 16);
        await sleep(600);

        // Heal confirmation
        addLog(ts() + `update permanent active`);
        
        // Transaction committed successfully: release all WAL tracking!
        setTrackedApp(Array(16).fill(false));
        setTrackedStaging(Array(16).fill(false));

        setWalMeta({
          seq: 48,
          intent: 'TOOB_WAL_INTENT_CONFIRM_COMMIT',
          details: 'Update committed. Clean Staging.',
          erase: 12,
          crc: '0xE8D7C6B5',
        });
        setWalSectors(['blkWal', 'blkWal', 'blkWalActive', 'blkEmpty']);
        await sleep(400);
        setBootSuccess(true);
        setStagingSectors(Array(16).fill('blkEmpty'));
        setScratchSectors(Array(16).fill('blkEmpty')); // Clear scratch at native position
        setWalSectors(['blkWal', 'blkWal', 'blkWal', 'blkEmpty']);

        // Loop pause before reset
        await sleep(5000);

        dlCut = false;
        reconCut = false;
        swapCut = false;
        swapIndex = 0;
      }
    };

    runSimulationLoop();

    return () => {
      activeRef.current = false;
      if (loopTimeout) clearTimeout(loopTimeout);
    };
  }, []);

  // Compute inline styles with scaling and Y offset transforms for .blocks containers only (Deprecated)
  const scratchBlocksStyle = {};
  const appBlocksStyle = {};

  return (
    <div className={styles.panel} aria-label="Live model of a Toob-Boot update transaction">
      <div className={styles.panelBody}>
        {/* Flicker effect */}
        <div className={`${styles.flicker} ${flicker ? styles.flickerGo : ''}`} />

        <div className={styles.flashCol}>
          <div className={styles.slotsContainer} ref={slotsContainerRef}>
            {/* Outlines represent tracking dynamically */}

            {/* STAGING SLOT */}
            <div className={styles.mapRow} ref={stagingRef}>
              <div className={styles.mapHead}>
                <span>STAGING-SLOT</span>
                <span className={styles.addr}>0x0806_0000</span>
              </div>
              <div className={styles.blocks}>
                {[0, 1, 2, 3].map((qIdx) => (
                  <div key={`stg-q-${qIdx}`} className={styles.quadrant}>
                    {stagingSectors.slice(qIdx * 4, qIdx * 4 + 4).map((state, localIdx) => {
                      const idx = qIdx * 4 + localIdx;
                      return (
                        <span 
                          key={`staging-${idx}`} 
                          className={`${styles.blk} ${styles[state] || ''} ${trackedStaging[idx] ? styles.walTracked : ''}`} 
                        />
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>

            {/* SCRATCH SLOT */}
            <div className={styles.mapRow} ref={scratchRef}>
              <div className={styles.mapHead}>
                <span>SCRATCH-SLOT</span>
                <span className={styles.addr}>0x0804_0000</span>
              </div>
              <div className={styles.blocks} style={scratchBlocksStyle}>
                {[0, 1, 2, 3].map((qIdx) => (
                  <div key={`scr-q-${qIdx}`} className={styles.quadrant}>
                    {scratchSectors.slice(qIdx * 4, qIdx * 4 + 4).map((state, localIdx) => {
                      const idx = qIdx * 4 + localIdx;
                      const inlineStyle = state === 'blkTorn' && tornBlockIndex === idx 
                        ? { background: `linear-gradient(180deg, #ef4444 0 ${tornPct}%, transparent ${tornPct}%)`, borderColor: '#ef4444' }
                        : undefined;

                      return (
                        <span 
                          key={`scratch-${idx}`} 
                          className={`${styles.blk} ${styles[state] || ''} ${trackedScratch[idx] ? styles.walTracked : ''}`} 
                          style={inlineStyle}
                        />
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>

            {/* APP SLOT */}
            <div className={styles.mapRow} ref={appRef}>
              <div className={styles.mapHead}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>APP-SLOT</span>
                  
                  {bootSuccess && (
                    <span className={styles.secureBadgeMini}>
                      <svg width="12" height="8" viewBox="0 0 6 4" fill="#2E9E5B" style={{ flexShrink: 0, display: 'block' }}>
                        <rect x="0" y="1" width="1" height="1" />
                        <rect x="1" y="2" width="1" height="1" />
                        <rect x="2" y="3" width="1" height="1" />
                        <rect x="3" y="2" width="1" height="1" />
                        <rect x="4" y="1" width="1" height="1" />
                        <rect x="5" y="0" width="1" height="1" />
                      </svg>
                      <span>SECURE</span>
                    </span>
                  )}
                </div>
                <span className={styles.addr}>0x0800_8000</span>
              </div>
              <div className={styles.blocks} style={appBlocksStyle}>
                {[0, 1, 2, 3].map((qIdx) => (
                  <div key={`app-q-${qIdx}`} className={styles.quadrant}>
                    {appSectors.slice(qIdx * 4, qIdx * 4 + 4).map((state, localIdx) => {
                      const idx = qIdx * 4 + localIdx;
                      const inlineStyle = state === 'blkTorn' && tornBlockIndex === idx 
                        ? { background: `linear-gradient(180deg, #ef4444 0 ${tornPct}%, transparent ${tornPct}%)`, borderColor: '#ef4444' }
                        : undefined;

                      return (
                        <span 
                          key={`app-${idx}`} 
                          className={`${styles.blk} ${styles[state] || ''} ${trackedApp[idx] ? styles.walTracked : ''}`} 
                          style={inlineStyle}
                        />
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>

            {/* WAL-JOURNAL */}
            <div className={styles.mapRow} ref={walRef}>
              <div className={styles.mapHead}>
                <span>WAL-JOURNAL (Flight Recorder)</span>
                <span className={styles.addr}>0x080C_0000</span>
              </div>
              <div className={styles.blocksWal}>
                {[0, 1, 2, 3].map((idx) => (
                  <div key={`wal-q-${idx}`} className={styles.walQuadrant}>
                    <span 
                      className={`${styles.blkWal} ${styles[walSectors[idx]] || ''} ${idx === activeWalSec ? styles.walTracked : ''}`} 
                    />
                  </div>
                ))}
              </div>
            </div>

            {/* Active absolute-positioned ghost blocks rendered on top of rows */}
            {activeTransfers.map((t) => {
              return (
                <div 
                  key={t.id} 
                  className={`${styles.ghostBlock} ${
                    t.type === 'dl' ? styles.ghostDl :
                    t.type === 'stgToScr' ? styles.ghostStgToScr :
                    t.type === 'appToScr' ? styles.ghostAppToScr :
                    t.type === 'swap' ? styles.ghostScrToApp :
                    t.type === 'appToStg' ? styles.ghostRollback :
                    t.type === 'walWrite' ? styles.ghostWalWrite :
                    styles.ghostRollback
                  }`} 
                  style={{
                    left: `${getTransferLeft(t.type, t.index, t.step)}px`,
                    width: `${getTransferWidth(t.type, t.index, t.step)}px`,
                    top: `${getTransferTop(t.type, t.step)}px`,
                    opacity: t.type === 'dl' && t.step === 0 ? 0 : 1,
                  }} 
                />
              );
            })}
          </div>
        </div>

        {/* Action Controls */}
        <div className={styles.ctrl}>
          <div className={styles.walPulseCol}>
            TMR State:
            <span className={styles.walCells}>
              {[0, 1, 2].map((idx) => (
                <span 
                  key={`wal-${idx}`} 
                  className={`${styles.walCell} ${
                    tmrQuorum === 2 && idx === 0 ? styles.walCellError : styles.walCellOn
                  } ${walPulsing ? styles.walCellPulse : ''}`} 
                />
              ))}
            </span>
            <span className={styles.quorum}>quorum {tmrQuorum}/3</span>
          </div>

          <button 
            type="button"
            className={styles.cut} 
            onClick={handleCutClick}
            disabled={!isUpdating || isBlackout || cutRequested}
          >
            CUT POWER
          </button>
        </div>

        {/* Terminal Log Console */}
        <div className={styles.log} aria-live="polite">
          {logs.map((log, idx) => (
            <div 
              key={`log-${idx}`} 
              className={styles.logLine} 
              dangerouslySetInnerHTML={{ __html: log.html }}
            />
          ))}
        </div>

        <div className={`${styles.blackoutScreen} ${isBlackout ? styles.blackoutActive : ''}`} />
      </div>
    </div>
  );
}
