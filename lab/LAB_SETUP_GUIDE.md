# SOCMind AI — Virtual Lab Setup Guide (Section 9.3)

This guide builds the deployment/lab architecture from the project document: a
Windows 11 host running SOCMind AI, an isolated virtual network, monitored VMs
(Windows 10, Ubuntu, Metasploitable) and a Kali attacker.

> **Safety:** everything here runs on an **isolated** virtual network. No attack
> touches any real or external system. Snapshot every VM before running scenarios.

```
Windows 11 Host [ SOCMind AI: Angular · FastAPI · PostgreSQL · Redis · Detection · AI ]
        |  Virtual Network (host-only / internal, e.g. 192.168.56.0/24)
   +----+-------------------+--------------------+
   |                        |                    |
Windows 10 Endpoint     Ubuntu Server      Metasploitable Target
   192.168.56.30         192.168.56.20        192.168.56.40
                        ^
                        |  attacks
                    Kali Linux  192.168.56.66
```

---

## 0. Prerequisites (on the Windows 11 host)

- **Docker Desktop** (you already run SOCMind with it).
- **VirtualBox** (free) *or* **VMware Workstation**. This guide uses VirtualBox;
  VMware notes are inline.
- ~40 GB free disk and 16 GB RAM recommended (each VM uses 2–4 GB).

Download ISOs/appliances:
- Ubuntu Server 22.04 LTS — ubuntu.com/download/server
- Windows 10 evaluation — Microsoft Evaluation Center
- Metasploitable 2 — SourceForge (pre-built appliance)
- Kali Linux — kali.org/get-kali (VirtualBox image)

---

## 1. Create the isolated network

**VirtualBox → File → Host Network Manager → Create.** You get a `vboxnet0`
adapter, typically `192.168.56.1/24`. Leave its DHCP server **disabled** — we use
static IPs. This is the "virtual network" in the diagram, and it's isolated from
the internet.

*VMware:* use a **Host-only** network (VMnet1) or a custom **LAN segment**.

Give every VM **one adapter attached to this host-only network**. (If a VM needs
internet to install packages first, temporarily add a second NAT adapter, then
remove it before running attack scenarios.)

Your Windows 11 host is reachable from the VMs at `192.168.56.1`, so the SOCMind
backend is at **`http://192.168.56.1:8000`**.

> Make sure Docker exposes the backend on all interfaces. Our compose maps
> `8000:8000`, which binds `0.0.0.0`, so the VMs can reach it. If Windows
> Firewall blocks it, allow inbound TCP 8000 for the host-only network.

---

## 2. Start SOCMind AI on the host

```powershell
cd "F:\My_Projects\SOCMind AI\socmind-ai"
docker compose up
cd frontend; npm start   # console at http://localhost:4200
```

Log in (admin@socmind.io / ChangeMe123!). Keep it running.

---

## 3. Register the assets in SOCMind

In the **Assets** screen, add each monitored VM so the collectors' events resolve
(the `hostname` must match what the collector sends):

| Hostname            | OS           | IP             | Criticality |
|---------------------|--------------|----------------|-------------|
| UBUNTU-SERVER-01    | Ubuntu 22.04 | 192.168.56.20  | High        |
| WIN10-ENDPOINT-01   | Windows 10   | 192.168.56.30  | Medium      |

(UBUNTU-SERVER-01 already exists from the seed.)

---

## 4. Ubuntu Server — monitored asset

1. Install Ubuntu Server, set a static IP `192.168.56.20` on the host-only adapter.
2. Ensure SSH is running: `sudo apt install openssh-server -y`.
3. Copy the Linux collector to the VM (`collectors/linux/authlog_collector.py`).
4. Run it:
   ```bash
   sudo apt install python3-pip -y && pip3 install requests
   python3 authlog_collector.py \
       --backend http://192.168.56.1:8000 \
       --asset UBUNTU-SERVER-01 \
       --logfile /var/log/auth.log
   ```
   It tails `auth.log` and ships SSH auth events to SOCMind.

---

## 5. Windows 10 — monitored asset

1. Install Windows 10, static IP `192.168.56.30`.
2. (Optional but recommended) install **Sysmon** for process telemetry.
3. Copy `collectors/windows/authlog_collector.ps1` to the VM.
4. In an **Administrator** PowerShell:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\authlog_collector.ps1 -Backend "http://192.168.56.1:8000" -Asset "WIN10-ENDPOINT-01"
   ```
   It reads Security events 4624/4625 (and Sysmon 1) and ships them.

---

## 6. Metasploitable — vulnerable target

Import the Metasploitable 2 appliance, attach it to the host-only network, static
IP `192.168.56.40`. It's the practice target for scans/exploits from Kali. (No
collector runs on it; it's a victim.)

---

## 7. Kali Linux — the attacker (simulation only)

Static IP `192.168.56.66`. Use Kali to generate the scenarios SOCMind detects.
**Only target the lab VMs.**

**SSH brute force → compromise** (against Ubuntu):
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20 -t 4
```
Watch SOCMind: failed logins correlate into a brute-force incident; a success
escalates it to **critical** with the attack story and graph.

**Port scan / recon** (against Metasploitable):
```bash
nmap -sS -p 1-1000 192.168.56.40
```

**RDP brute force** (against Windows 10):
```bash
hydra -l Administrator -P passwords.txt rdp://192.168.56.30
```

If you can't SSH-brute in the time available, you can still demonstrate the full
pipeline from the host with the scripted generator:
```powershell
python backend/scripts/demo_scenarios.py
```

---

## 8. Demo flow (what to show)

1. Kali runs the SSH brute force → SOCMind **Dashboard** shows a new critical incident.
2. Open the incident → **kill chain**, **attack graph**, **attack story**, **AI
   assistant** with recommended commands.
3. **Response actions** → propose *Isolate endpoint* → **Approvals** → approve →
   **Undo**. Everything lands in the **Audit Trail**.
4. **Decision Panel** shows the reasoning; **Reports** exports the case as PDF/CSV/JSON.

---

## Troubleshooting

- **VM can't reach the backend:** confirm `curl http://192.168.56.1:8000/health`
  from the VM. If it fails, check Windows Firewall inbound rule for TCP 8000 and
  that the VM is on the host-only adapter.
- **No incidents appear:** confirm the asset hostname in SOCMind exactly matches
  the collector's `--asset` value; check the collector console for "sent" lines.
- **Backend not on 192.168.56.1:** run `ipconfig` on the host and use the
  host-only adapter's IPv4 address in the collector `--backend` flag.
