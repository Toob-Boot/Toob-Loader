# Runbook: Production Control-Plane Autonomy Verification (OPS-081)

## Overview
This runbook details the procedure for executing a single manual control-plane shutdown verification test in Production during a low-traffic maintenance window.

---

## Prerequisites & Safety
- **Timing:** Off-peak maintenance window (e.g., 03:00 AM UTC).
- **Communication:** Notify operations on-call team prior to execution.
- **External Host:** Execute probes from an independent external workstation (outside `10.9.0.0/16` and Hetzner VPC).

---

## Step-by-Step Procedure

1. **Initiate Maintenance Window Mode:**
   - Log into `ops-hub` (`10.9.1.2`).
2. **Temporarily Suspend Control-Plane Tunnel:**
   ```bash
   sudo systemctl stop wg-quick@wg0-hub
   ```
3. **Execute External Autonomy Probe (from external workstation):**
   ```bash
   ./deploy/scripts/verify-autonomy.sh production
   ```
4. **Verify Core Workloads:**
   - [ ] `registry.the-toob.com/health` returns `HTTP 200`.
   - [ ] `id.the-toob.com/health` returns `HTTP 200`.
   - [ ] `ota.the-toob.com/health` returns `HTTP 200`.
   - [ ] `fw.the-toob.com/firmware.bin` range request returns `HTTP 416`.
   - [ ] MCU device check-in completes successfully.
5. **Restore Control-Plane Tunnel:**
   ```bash
   sudo systemctl start wg-quick@wg0-hub
   ```
6. **Confirm Telemetry Recovery:**
   - Verify Grafana `toob-ops` dashboards resume telemetry scraping within 2 minutes.
