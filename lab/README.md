# SOCMind AI — Virtual Lab

An isolated virtual network on the Windows 11 host. **Nothing here touches any
external or production system** — all attacks are simulated in the lab only.

## VMs

| VM                    | Role                     | Notes                                  |
|-----------------------|--------------------------|----------------------------------------|
| Windows 11 Host       | Runs SOCMind AI          | Angular · FastAPI · PostgreSQL · Redis |
| Ubuntu Server         | Monitored asset          | Runs the Linux auth.log collector      |
| Windows 10 Endpoint   | Monitored asset          | Sysmon + Windows Event Log (later)     |
| Metasploitable        | Vulnerable target        | Practice target                        |
| Kali Linux            | Attacker (simulation)    | Generates the lab attack scenarios     |

## Networking

- Use a **Host-Only** or **Internal** network in VirtualBox/VMware so the lab
  cannot reach the internet.
- Example subnet: `192.168.56.0/24`.
  - Host (SOCMind backend reachable at): `192.168.56.1:8000`
  - Ubuntu Server: `192.168.56.20`
  - Kali attacker: `192.168.56.66`
- **Snapshot every VM** before running scenarios so you can roll back.

## First scenario: SSH brute force

1. On Ubuntu, install requests and run the collector:
   ```bash
   pip install requests
   python3 authlog_collector.py --backend http://192.168.56.1:8000 \
       --asset UBUNTU-SERVER-01 --logfile /var/log/auth.log
   ```
2. From Kali, brute-force SSH against Ubuntu (lab only):
   ```bash
   hydra -l root -P rockyou.txt ssh://192.168.56.20
   ```
3. Watch SOCMind correlate the failures into a single incident, with an audit
   trail, in the API (`GET /api/incidents`) and later the dashboard.

> Register each monitored asset in SOCMind first (hostname must match the
> `--asset` value the collector sends).
