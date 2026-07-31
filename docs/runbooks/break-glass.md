# Runbook: Emergency Break-Glass & Out-of-Band Incident Recovery (OPS-022)

## Overview
This runbook defines the emergency out-of-band access procedures when the central control plane (`ops-hub`) or central WireGuard VPN tunnel is completely unreachable, down, or compromised.

> [!CAUTION]
> **Break-Glass Principles:**
> 1. Under normal operation, zero public TCP ports (including SSH port 22) are open to the internet.
> 2. Break-glass procedures must bypass standard WireGuard hub routing **without** permanently relaxing firewall security boundaries.
> 3. All break-glass activations MUST be logged, timed, and audited. Target SLA for regaining administrative SSH access is **< 15 minutes**.

---

## Emergency Access Paths

```
                             ┌────────────────────────────────────────┐
                             │    ops-hub / WireGuard VPN Down        │
                             └───────────────────┬────────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        │                                                 │
                        ▼                                                 ▼
        ┌───────────────────────────────┐                 ┌───────────────────────────────┐
        │  PATH 1: Out-of-Band Console  │                 │   PATH 2: Standby Emergency   │
        │  (Hetzner VNC / Rescue Mode)  │                 │     WireGuard Interface       │
        └───────────────┬───────────────┘                 └───────────────┬───────────────┘
                        │                                                 │
                        ▼                                                 ▼
        ┌───────────────────────────────┐                 ┌───────────────────────────────┐
        │ Serial VNC or Emergency Key   │                 │ Activate dormant              │
        │ Injection via Hetzner API     │                 │ /etc/wireguard/wg-emergency   │
        └───────────────────────────────┘                 └───────────────────────────────┘
```

---

## Procedure 1: Hetzner Cloud VNC Serial Console Access (Primary Path)

The primary break-glass path uses Hetzner's hardware-isolated serial VNC console. It requires no network services or public ports on the target machine.

### Step 1.1 — Access Hetzner Console
1. Log into the [Hetzner Cloud Console](https://console.hetzner.cloud).
2. Select the target project (e.g., `toob-ops`, `toob-registry`, `toob-identity`, `toob-update`).
3. Click on the affected server node (e.g., `reg-api-fsn1`, `ops-hub`).
4. Click **Console** in the top-right menu to open the VNC web console.

### Step 1.2 — Login via VNC
1. Authenticate with root credentials or emergency operator credentials.
2. If root password login is disabled, use **Hetzner Rescue System**:
   - Go to **Rescue** -> **Enable Rescue & Power Cycle**.
   - Reboot node into Hetzner Linux Rescue Environment.
   - Mount host disk:
     ```bash
     mount /dev/sda1 /mnt
     # Copy emergency SSH public key to authorized_keys
     echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." >> /mnt/root/.ssh/authorized_keys
     umount /mnt
     reboot
     ```

---

## Procedure 2: Standby Emergency WireGuard Profile Activation (Secondary Path)

Each spoke node maintains a dormant emergency WireGuard configuration (`/etc/wireguard/wg-emergency.conf.disabled`).

### Step 2.1 — Enable Emergency WireGuard Interface via API or Script
If `ops-hub` is down, run the break-glass helper script from an administrative workstation with Hetzner API access:

```bash
# Check status of ops-hub and spoke nodes
./deploy/scripts/break-glass.sh status

# Enable dormant emergency WireGuard interface on target spoke node
./deploy/scripts/break-glass.sh enable-emergency --server reg-api-fsn1
```

### Step 2.2 — Direct Emergency Dial-Out
Once `wg-emergency` is enabled on the target node, dial out directly to the node's public IP using your emergency WireGuard profile:

```bash
wg-quick up ./wg-admin-keys/toob-emergency.conf
ssh -i ~/.ssh/id_ed25519 root@10.253.0.1
```

---

## Procedure 3: Recovery & Re-Hardening

Once the incident is resolved and `ops-hub` is restored to healthy operation:

1. **Disable Emergency WireGuard Interface:**
   ```bash
   ./deploy/scripts/break-glass.sh disable-emergency --server reg-api-fsn1
   ```
2. **Verify Firewall Integrity:**
   Verify that zero public TCP ports respond on the node's public IP:
   ```bash
   nmap -Pn -p 22,80,443,8200 <node-public-ip>
   ```
3. **Log Incident Metrics:**
   Document the break-glass drill or incident metrics in the table below.

---

## Break-Glass Drill Protocol & Log Matrix

| Date | Trigger / Scenario | Executing Operator | Path Used | Time to Access (SLA < 15m) | Status | Notes |
|---|---|---|---|---|---|---|
| 2026-07-31 | Initial OPS-022 Break-Glass Drill | DevOps Lead | Path 1 (VNC) & Path 2 (Emergency WG) | 4 min 12 sec | SUCCESS | Verified out-of-band access and immediate re-hardening |
