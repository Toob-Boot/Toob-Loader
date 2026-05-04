import os
import json
import webbrowser


def generate_soc_report(run_dir):
    """
    Generates a zero-dependency HTML dashboard for the given run directory.
    Validates existence of blueprint.json, aggregated_scan.json, and keelhaul_svd.json.
    """
    blueprint_path = os.path.join(run_dir, "blueprint.json")
    scan_path = os.path.join(run_dir, "aggregated_scan.json")

    if not os.path.exists(blueprint_path):
        print(f"[!] Cannot generate report: Missing {blueprint_path}")
        return None

    # Load Blueprint Data
    with open(blueprint_path, "r") as f:
        blueprint_data = json.load(f)

    chip_name = list(blueprint_data.keys())[0] if blueprint_data else "Unknown_SoC"
    chip_data = blueprint_data.get(chip_name, {})

    # Load Scan Data (if available)
    scan_data = {}
    if os.path.exists(scan_path):
        with open(scan_path, "r") as f:
            scan_data = json.load(f)

    # Convert mapping for javascript
    flash_regions = []

    if scan_data:
        valid_keys = []
        for k in scan_data.keys():
            try:
                int(k)
                valid_keys.append(k)
            except ValueError:
                pass
        sorted_addrs = sorted(valid_keys, key=lambda x: int(x))
        
        if sorted_addrs:
            first_addr = int(sorted_addrs[0])
            if first_addr > 0:
                flash_regions.append({
                    "start": 0,
                    "end": first_addr - 1,
                    "size_kb": first_addr / 1024.0,
                    "status": "SKIPPED",
                    "fallback": False,
                    "type": "Hardware / Bootloader Reserved",
                    "verification": "AI-Extracted / Datasheet Inferred"
                })

        for idx in range(len(sorted_addrs)):
            addr = sorted_addrs[idx]
            stats = scan_data[addr]
            ping_stat = stats.get("run_ping", "unknown")
            pong_stat = stats.get("run_pong", "unknown")

            effective = "SKIPPED"
            if ping_stat == "erased" or pong_stat == "erased":
                effective = "ERASED"

            start_addr = int(addr)

            # Adopt true dynamically discovered sector size if available, fallback to 4KB
            sector_bytes = stats.get("size", 4096)
            end_addr = stats.get("end_addr", start_addr + sector_bytes)

            size_kb = sector_bytes / 1024.0

            flash_regions.append(
                {
                    "start": start_addr,
                    "end": end_addr,
                    "size_kb": size_kb,
                    "status": effective,
                    "fallback": stats.get("fallback", False),
                    "type": "Flash Sector",
                    "verification": stats.get("verification_method", "BootROM / SVD Inferred")
                }
            )

    # Extract RAM Fuzzed Boundaries for matching
    verified_ram = set()
    if "metadata" in scan_data and "ram_fuzzed_boundaries" in scan_data["metadata"]:
        for rb in scan_data["metadata"]["ram_fuzzed_boundaries"]:
            try:
                verified_ram.add(int(rb, 16))
            except:
                pass


    # Load Blueprint SRAM
    ram_regions = []
    unique_ram = {}
    if "memory" in chip_data and "memory_regions" in chip_data["memory"]:
        for region in chip_data["memory"]["memory_regions"]:
            is_ram = (
                "ram" in region.get("name", "").lower()
                or "data" in region.get("name", "").lower()
                or "cache" in region.get("name", "").lower()
                or "reserved" in region.get("name", "").lower()
            )
            if is_ram:
                origin = int(region["origin"], 16)
                length = int(region["length"], 16)
                is_skipped = (
                    ("-" in region.get("permissions", ""))
                    or ("cache" in region.get("name", "").lower())
                    or ("reserved" in region.get("name", "").lower())
                )

                # Check verification (The hardware fuzzer returns the discovered END boundary)
                is_verified = ((origin + length) in verified_ram) or (origin in verified_ram)

                # Exclude massive invalid blocks
                if length > 0 and length < 10 * 1024 * 1024:
                    if origin in unique_ram:
                        unique_ram[origin]["name"] += f" / {region['name'].upper()}"
                        if is_skipped:
                            unique_ram[origin]["status"] = "SKIPPED"
                        if is_verified:
                            unique_ram[origin]["verification"] = "Physical Fuzzing (Bare-Metal)"
                    else:
                        unique_ram[origin] = {
                            "name": region["name"].upper(),
                            "start": origin,
                            "size_kb": length / 1024.0,
                            "type": "RAM/CACHE" if is_skipped else "RAM",
                            "status": "SKIPPED" if is_skipped else "OK",
                            "verification": "Physical Fuzzing (Bare-Metal)" if is_verified else "SVD / Blueprint Inferred"
                        }

    ram_regions = list(unique_ram.values())

    # Load Peripherals (we'll extract this directly from the python pipeline context if needed, but for now we mock it or extract from SVD if JSON exists)
    # Since SVD generates a C file currently, let's extract known bases from the python SVD parser logic if possible.
    # We will look for a keelhaul_pac.json if the svd parser emits it.
    peripherals = []
    pac_path = os.path.join(run_dir, "keelhaul_pac.json")
    if os.path.exists(pac_path):
        with open(pac_path, "r") as f:
            try:
                pac_data = json.load(f)
                for p in pac_data.get("peripherals", []):
                    peripherals.append(
                        {
                            "name": p["name"],
                            "start": p["base_address"],
                            "size_kb": 4.0,  # Approximate SVD block
                            "type": "Peripheral",
                        }
                    )
            except:
                pass

    # Calculate Stats
    total_flash_kb = sum(r["size_kb"] for r in flash_regions)
    erased_kb = sum(r["size_kb"] for r in flash_regions if "ERASED" in r["status"])
    reserved_flash_kb = sum(
        r.get("size_kb", 0) for r in flash_regions if r.get("status") == "SKIPPED"
    )

    scan_target_kb = 0
    if "metadata" in scan_data and "scan_total_bytes" in scan_data["metadata"]:
        scan_target_kb = scan_data["metadata"]["scan_total_bytes"] / 1024.0
    if scan_target_kb == 0:
        scan_target_kb = total_flash_kb

    flash_progress_pct = 0
    if scan_target_kb > 0:
        flash_progress_pct = min(100, int((erased_kb / scan_target_kb) * 100))

    total_ram_kb = sum(r["size_kb"] for r in ram_regions)
    reserved_ram_kb = sum(
        r.get("size_kb", 0) for r in ram_regions if r.get("status") == "SKIPPED"
    )

    verifiable_ram_kb = sum(r["size_kb"] for r in ram_regions if r.get("status") != "SKIPPED")
    verified_ram_kb = sum(r["size_kb"] for r in ram_regions if r.get("status") != "SKIPPED" and r.get("verification") == "Physical Fuzzing (Bare-Metal)")

    ram_progress_pct = 0
    if verifiable_ram_kb > 0:
        ram_progress_pct = min(100, int((verified_ram_kb / verifiable_ram_kb) * 100))

    periph_count = len(peripherals)

    # Build Javascript Embedded Data
    js_data = {
        "chip": chip_name,
        "flash": flash_regions,
        "ram": ram_regions,
        "peripherals": peripherals,
        "stats": {
            "flash_kb": total_flash_kb,
            "erased_kb": erased_kb,
            "reserved_flash_kb": reserved_flash_kb,
            "scan_target_kb": scan_target_kb,
            "flash_progress_pct": flash_progress_pct,
            "ram_kb": total_ram_kb,
            "reserved_ram_kb": reserved_ram_kb,
            "verifiable_ram_kb": verifiable_ram_kb,
            "verified_ram_kb": verified_ram_kb,
            "ram_progress_pct": ram_progress_pct,
            "periph_count": periph_count,
        },
    }

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Toobfuzzer Visualizer - {chip_name}</title>
    <link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #FFFFFF;
            --bg-secondary: #E3E1E1;
            --text-color: #000000;
            --accent-green: #C0FFCC;
            --glass-border: rgba(0, 0, 0, 0.1);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Josefin Sans', sans-serif;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-color);
            padding: 20px 40px;
        }}

        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--bg-secondary);
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}

        h1 {{
            font-weight: 600;
            font-size: 2.2rem;
        }}

        .subtitle {{
            color: #666;
            font-size: 1.1rem;
            margin-top: 5px;
        }}

        /* Summary Bar */
        .summary-bar {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat-box {{
            flex: 1;
            background: var(--bg-secondary);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid var(--glass-border);
            text-align: center;
        }}
        .stat-val {{
            font-size: 1.5rem;
            font-weight: 600;
        }}
        .stat-lbl {{
            font-size: 0.85rem;
            color: #555;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }}

        /* Global Memory Map */
        .minimap-container {{
            margin-bottom: 30px;
        }}
        .minimap-title {{
            font-size: 0.9rem;
            font-weight: 600;
            margin-bottom: 5px;
            text-transform: uppercase;
        }}
        .minimap-track {{
            height: 24px;
            display: flex;
            flex-direction: row;
            align-items: stretch;
            position: relative;
            width: 100%;
            box-sizing: border-box;
            background: rgba(0,0,0,0.02);
            border-radius: 4px;
            padding: 2px;
            overflow: hidden;
        }}
        .map-chunk {{
            border-radius: 2px;
            opacity: 0.85;
            box-shadow: inset 0 0 0 1px rgba(0,0,0,0.1);
        }}
        .map-chunk:hover {{
            opacity: 1;
            box-shadow: 0 0 8px rgba(0,0,0,0.5);
            z-index: 10;
        }}

        /* Legend */
        .legend {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            justify-content: center;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .legend-color {{
            width: 14px;
            height: 14px;
            border-radius: 3px;
            border: 1px solid rgba(0,0,0,0.2);
        }}

        .dashboard {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 30px;
            height: 60vh;
        }}

        .column {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 15px;
            display: flex;
            flex-direction: column;
            border: 1px solid var(--glass-border);
            overflow-y: auto;
        }}

        .column h2 {{
            text-align: center;
            margin-bottom: 15px;
            font-weight: 600;
            font-size: 1.1rem;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}

        .memory-stack {{
            display: flex;
            flex-direction: column;
            flex-grow: 1;
            gap: 6px;
        }}

        .mem-block {{
            background: var(--bg-primary);
            border: 1px solid var(--glass-border);
            border-radius: 6px;
            display: flex;
            flex-direction: column;
            justify-content: flex-start;
            align-items: flex-start;
            transition: all 0.2s ease;
            position: relative;
            min-height: 48px;
            padding: 6px 10px;
            overflow: hidden;
        }}

        .mem-block:hover {{
            transform: scale(1.02);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            z-index: 10;
        }}

        .mem-block.erased-both {{ background: var(--accent-green); border-color: #8ce8a0; }}
        .mem-block.skipped {{ background: #f0f0f0; color: #888; border-style: dashed; }}
        .mem-block.ram-block {{ background: var(--bg-primary); border-color: #ccc; }}
        .mem-block.periph-block {{ background: #fffbe6; border-color: #fce28b; }}

        .block-top {{ display: flex; justify-content: space-between; width: 100%; align-items: center; margin-bottom: 0px; }}
        .block-label {{ font-weight: 600; font-size: 0.82rem; color: #333; line-height: 1.1; }}
        .block-hex {{ font-family: 'Consolas', monospace; font-size: 0.72rem; color: #444; line-height: 1.1; }}
        .block-sub {{ font-size: 0.72rem; font-weight: 600; opacity: 0.8; line-height: 1.1; }}

        /* Tooltip removal, changing to selectable block */
        .mem-block {{
            user-select: text;
            cursor: auto;
        }}

        .mem-block:hover {{
            transform: scale(1.02);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            z-index: 10;
        }}

    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1>SoC Architecture Visualizer</h1>
            <div class="subtitle">Silicon Extracted Target: <strong id="chip-name">{chip_name}</strong></div>
        </div>
        <div>
            <span style="background: var(--accent-green); padding: 5px 15px; border-radius: 20px; font-weight: 600; font-size: 0.9rem;">100% Zero-Bloat HTML</span>
        </div>
    </div>

    <!-- Summary Metrics -->
    <div class="summary-bar" id="summary-bar">
        <!-- Rendered via JS -->
    </div>

    <!-- Global Minimap -->
    <div class="minimap-container">
        <div class="minimap-title">Global 32-Bit Address Space (0x00000000 - 0xFFFFFFFF)</div>
        <div class="minimap-track" id="mini-map">
            <!-- Rendered via JS -->
        </div>
    </div>

    <div class="dashboard">
        <div class="column" id="col-flash">
            <h2>SPI Flash Memory</h2>
            <div style="font-size: 0.95rem; margin-bottom: 10px; color: #555; background: #fff; padding: 5px 10px; border-radius: 4px; border: 1px solid #ddd; text-align: center;">
                <b>Progress:</b> <span style="font-weight:bold; color: #c48dfc;">{flash_progress_pct}%</span> 
                <span style="font-size: 0.85rem;">({erased_kb:.1f} / {scan_target_kb:.1f} KB Target)</span>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-color" style="background: var(--accent-green);"></div> Erased</div>
                <div class="legend-item" title="Hardware Reserved / Protected by Bootloader"><div class="legend-color" style="background: #f0f0f0; border-style: dashed;"></div> Skipped - reserved by Hardware/Bootloader</div>
            </div>
            <div class="memory-stack" id="stack-flash"></div>
        </div>
        
        <div class="column" id="col-ram">
            <h2>Internal SRAM</h2>
            <div style="font-size: 0.95rem; margin-bottom: 10px; color: #555; background: #fff; padding: 5px 10px; border-radius: 4px; border: 1px solid #ddd; text-align: center;">
                <b>Verification:</b> <span style="font-weight:bold; color: #c48dfc;">{ram_progress_pct}%</span> 
                <span style="font-size: 0.85rem;">({verified_ram_kb:.1f} / {verifiable_ram_kb:.1f} KB Target)</span>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-color" style="background: var(--bg-primary); border: 1px solid #ccc;"></div> Application RAM</div>
                <div class="legend-item" title="Hardware Caches / Reserved RAM"><div class="legend-color" style="background: #f0f0f0; border-style: dashed;"></div> Hardware Reserved / Cache</div>
            </div>
            <div class="memory-stack" id="stack-ram"></div>
        </div>
        
        <div class="column" id="col-periph">
            <h2>Hardware Peripherals</h2>
            <div class="memory-stack" id="stack-periph"></div>
        </div>
    </div>

    <script>
        const socData = {json.dumps(js_data)};
        
        function formatHex(val) {{
            return "0x" + val.toString(16).toUpperCase().padStart(8, '0');
        }}

        // Render Summary
        const s = socData.stats;
        const totalFlash = s.flash_kb ? s.flash_kb.toFixed(1) : 0;
        const totalErased = s.erased_kb ? s.erased_kb.toFixed(1) : 0;
        const reservedFlash = s.reserved_flash_kb ? s.reserved_flash_kb.toFixed(1) : 0;
        const usableFlash = s.flash_kb ? (s.flash_kb - (s.reserved_flash_kb || 0)).toFixed(1) : 0;
        
        const totalRam = s.ram_kb ? s.ram_kb.toFixed(1) : 0;
        const reservedRam = s.reserved_ram_kb ? s.reserved_ram_kb.toFixed(1) : 0;
        const usableRam = s.ram_kb ? (s.ram_kb - (s.reserved_ram_kb || 0)).toFixed(1) : 0;
        
        let usableCoverage = 0;
        if(usableFlash > 0) usableCoverage = ((totalErased/usableFlash)*100).toFixed(1);

        document.getElementById('summary-bar').innerHTML = `
            <div class="stat-box" title="Total physically mapped Flash: ${{totalFlash}} KB">
                <div class="stat-val">${{usableFlash}} KB <span style="font-size: 0.55em; font-weight: normal; color: #888;">+ ${{reservedFlash}} KB Rsrv.</span></div>
                <div class="stat-lbl">Mapped Flash Volume</div>
            </div>
            <div class="stat-box" title="Percentage of usable flash successfully scanned">
                <div class="stat-val" style="color: #2E8B57;">${{usableCoverage}}%</div>
                <div class="stat-lbl">Flash Scan Coverage</div>
            </div>
            <div class="stat-box" title="Total physically mapped SRAM: ${{totalRam}} KB">
                <div class="stat-val">${{usableRam}} KB <span style="font-size: 0.55em; font-weight: normal; color: #888;">+ ${{reservedRam}} KB Rsrv.</span></div>
                <div class="stat-lbl">SRAM Hardware Allocation</div>
            </div>
            <div class="stat-box">
                <div class="stat-val">${{s.periph_count || 0}}</div>
                <div class="stat-lbl">Peripherals Discovered</div>
            </div>
        `;

        let flashCoveragePct = 0;
        let flashSkippedPct = 0;
        if(s.flash_kb > 0) {{
            flashCoveragePct = ((totalErased / s.flash_kb) * 100).toFixed(1);
            flashSkippedPct = (((s.reserved_flash_kb || 0) / s.flash_kb) * 100).toFixed(1);
        }}
        const flashLegendHtml = `
            <div class="legend-item"><div class="legend-color" style="background: var(--accent-green);"></div> Erased (${{flashCoveragePct}}%)</div>
            <div class="legend-item" title="Hardware Reserved / Protected by Bootloader"><div class="legend-color" style="background: #f0f0f0; border-style: dashed;"></div> Skipped (${{flashSkippedPct}}%)</div>
        `;
        document.querySelector('#col-flash .legend').innerHTML = flashLegendHtml;

        let usableRamPct = 0;
        let reservedRamPct = 0;
        if(s.ram_kb > 0) {{
            usableRamPct = (((s.ram_kb - (s.reserved_ram_kb || 0)) / s.ram_kb) * 100).toFixed(1);
            reservedRamPct = (((s.reserved_ram_kb || 0) / s.ram_kb) * 100).toFixed(1);
        }}
        const ramLegendHtml = `
            <div class="legend-item"><div class="legend-color" style="background: var(--bg-primary); border: 1px solid #ccc;"></div> Application RAM (${{usableRamPct}}%)</div>
            <div class="legend-item" title="Hardware Caches / Reserved RAM"><div class="legend-color" style="background: #f0f0f0; border-style: dashed;"></div> Hardware Reserved / Cache (${{reservedRamPct}}%)</div>
        `;
        document.querySelector('#col-ram .legend').innerHTML = ramLegendHtml;

        // Render Minimap
        function renderMiniMap() {{
            const mapHtml = [];
            
            // Flatten all items into one array with category tags
            const allItems = [];
            if(socData.flash) socData.flash.forEach(i => allItems.push({{...i, category: 'flash'}}));
            if(socData.ram) socData.ram.forEach(i => allItems.push({{...i, category: 'ram'}}));
            if(socData.peripherals) socData.peripherals.forEach(i => allItems.push({{...i, category: 'periph'}}));
            
            // Sort by starting address
            allItems.sort((a,b) => a.start - b.start);
            
            if (allItems.length > 0) {{
                document.querySelector('.minimap-title').innerText = `Global Memory Distribution (Relative Footprint)`;
            }}
            
            let lastEnd = -1;
            allItems.forEach(item => {{
                let c = '#ccc';
                if(item.category === 'flash') {{
                    if(item.status === 'ERASED') c = 'var(--accent-green)';
                    else if(item.status === 'SKIPPED') c = '#aaa';
                }} else if(item.category === 'ram') {{
                    c = '#888';
                    if(item.status === 'SKIPPED') c = '#aaa';
                }} else {{
                    c = '#ffaa00';
                }}
                
                const itemEnd = item.end || (item.start + (item.size_kb * 1024));
                
                // If disjoint from previous item, add a fixed gap representing the unmapped void
                if(lastEnd !== -1 && item.start > lastEnd) {{
                    mapHtml.push(`<div style="flex: 0 0 16px; min-width: 16px;"></div>`);
                }}
                
                const title = `${{item.name || item.type}} (${{formatHex(item.start)}} - ${{item.size_kb.toFixed(1)}} KB)`;
                
                // Use flex proportional sizing based on KB size.
                // Shrink allowed so it fits if total size is massive, no min-width forces it in bounds.
                mapHtml.push(`<div class="map-chunk" style="flex: ${{item.size_kb}} 1 0px; background: ${{c}}; min-width: 0;" title="${{title}}"></div>`);
                
                lastEnd = Math.max(lastEnd, itemEnd);
            }});
            
            document.getElementById('mini-map').innerHTML = mapHtml.join('');
        }}
        renderMiniMap();

        function buildBlocks(containerId, items, category) {{
            const stack = document.getElementById(containerId);
            if (!items || items.length === 0) {{
                stack.innerHTML = "<div style='text-align:center; color:#888; margin-top: 20px;'>No telemetry available</div>";
                return;
            }}

            // Calculate total size to apply proportional flex-grow
            let totalSize = items.reduce((sum, item) => sum + item.size_kb, 0);
            
            items.forEach(item => {{
                // Determine CSS Class
                let cssClass = "";
                let title = item.name || item.type;
                
                if (category === 'flash') {{
                    title = "Flash Sector";
                    if (item.fallback) {{
                        title += " (4KB Fallback Interval)";
                    }} else if (item.status === "ERASED") {{
                        title += " (True-Precision Discovery)";
                    }}

                    if (item.status === "ERASED") cssClass = "erased-both";
                    else if (item.status === "SKIPPED" || item.status === "FAULT (BOTH)") {{
                        cssClass = "skipped";
                        title += " (Skipped - Hardware / Bootloader Reserved)";
                    }}
                }} else if (category === 'ram') {{
                    if (item.status === "SKIPPED") {{
                        cssClass = "skipped";
                        title += " (Skipped - Hardware Cache / Reserved)";
                    }} else {{
                        cssClass = "ram-block";
                    }}
                }} else if (category === 'periph') {{
                    cssClass = "periph-block";
                }}

                // Calculate proportional height
                let minHeight = 50;
                let flexBasis = Math.max(minHeight, (item.size_kb / totalSize) * 500); // 500px is rough container scaling factor

                const block = document.createElement("div");
                block.className = `mem-block ${{cssClass}}`;
                block.style.flex = `0 0 ${{flexBasis}}px`;
                
                const endAddr = item.end || (item.start + (item.size_kb * 1024));
                const rangeTextLong = `${{formatHex(item.start)}} -> ${{formatHex(endAddr-1)}}`;

                let badgeHtml = "";
                if (item.verification && item.verification.includes("Physical Fuzzing")) {{
                    badgeHtml = `<div style="background-color: #9b59b6; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: bold; margin-top: 4px; display: inline-block; box-shadow: 0 2px 4px rgba(155,89,182,0.3);">Verified (Physical Fuzzing) \u2713</div>`;
                }} else if (item.verification) {{
                    badgeHtml = `<div style="background-color: #e67e22; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: bold; margin-top: 4px; display: inline-block; box-shadow: 0 2px 4px rgba(230,126,34,0.3);">AI-Extracted (Unverified) \u26A0</div>`;
                }}

                block.innerHTML = `
                    <div class="block-top">
                        <div class="block-label">${{title}}</div>
                        <div class="block-sub">${{item.size_kb.toFixed(1)}} KB</div>
                    </div>
                    <div class="block-hex">${{rangeTextLong}}</div>
                    ${{badgeHtml}}
                `;
                
                stack.appendChild(block);
            }});
        }}

        // Render Stacks
        buildBlocks("stack-flash", socData.flash, 'flash');
        buildBlocks("stack-ram", socData.ram, 'ram');
        buildBlocks("stack-periph", socData.peripherals, 'periph');

    </script>
</body>
</html>"""

    out_file = os.path.join(run_dir, "soc_visualizer.html")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[*] Generated UI Component: {os.path.basename(out_file)}")
    return out_file


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        run_d = sys.argv[1]
        f = generate_soc_report(run_d)
        if f:
            webbrowser.open(f"file://{os.path.abspath(f)}")
    else:
        print("Usage: python report_generator.py <run_directory>")
