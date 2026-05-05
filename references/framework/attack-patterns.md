# Attack Patterns — Cross-Platform Indicator Reference

Common attack chains seen in ransomware incidents. Use this to guide cross-platform correlation.

---

## Ransomware Attack Chain (Typical)

```
[Initial Access]
  → Exploit public-facing service (FW admin, VPN, RDP, Web)
  → Valid account (brute force or credential stuffing)
  → Phishing (credential harvest or malware delivery)

[Execution / Staging]
  → Upload tools via SMB share, RDP clipboard, or web shell
  → Execute via scheduled task, service installation, or WMI

[Persistence]
  → New admin account
  → Remote access tool (Chrome RDP, AnyDesk, TeamViewer)
  → Malicious service (NSSM + malware binary)
  → SSH authorized_keys (Linux)
  → Scheduled task / cron job

[Privilege Escalation]
  → Password dump (Mimikatz, secretsdump)
  → Pass-the-Hash / Pass-the-Ticket
  → Exploit local privilege vulnerability

[Lateral Movement]
  → SMB with harvested credentials (Type 3 login)
  → RDP with stolen credentials (Type 10 login)
  → SSH with stolen key or brute-forced password
  → WMI / PsExec / WinRM

[Defense Evasion]
  → Disable AV / Windows Defender
  → Clear event logs (EventID 1102)
  → Delete shadow copies (vssadmin / wmic)
  → Use LOLBins (certutil, mshta, wscript, bitsadmin)

[Collection / Exfiltration] (double extortion)
  → Enumerate shares, databases
  → Compress and exfiltrate before encryption

[Impact]
  → Delete/encrypt Veeam backups
  → Delete volume shadow copies
  → Encrypt files (.vhd/.vhdx for VMs, all user data)
  → Drop ransom note
  → Forced reboot
```

---

## Cross-Platform Correlation Map

| Phase | FortiGate | Windows Security | Windows System | Linux | Veeam |
|-------|-----------|-----------------|----------------|-------|-------|
| Initial Access | Login success from ext IP; config download | — | — | SSH accept from ext IP | — |
| Staging | SSH long session | 4624 Type 3 from FW IP | — | Session >2h | — |
| Persistence | — | 4720 new account; 4698 sched task | 7045 new service | useradd; cron; authorized_keys | — |
| Lateral Move | — | 4624 Type 3 internal IPs; 4648; NTLM V2 | — | Accepted from internal IP | — |
| Defense Evasion | — | 1102 log cleared; 4688 AV disable cmd | 7036 Defender stopped | rm auth.log; history -c | 331 service stopped |
| Backup Destruction | — | — | — | — | 190/191/560 |
| Pre-encryption | — | 4688 vssadmin/bcdedit | 7036 VSS stopped | — | 190/191 deletion |
| Encryption | — | 1074 (0x84050013) | 6008 unexpected shutdown; 6013 uptime=17s | — | 4 job failure (repo encrypted) |

---

## Time Gap Significance

| Gap | Interpretation |
|-----|---------------|
| FW login success → internal host login within <10 min | Direct pivot — FW used as jump host |
| External IP → internal brute force from same time window | Attacker already inside, pivoting |
| Password change (4738) → lateral login from same machine within minutes | Credential harvested and immediately used |
| Backup deletion → encryption within hours | Deliberate backup destruction before impact |
| AV stopped → new service installed within seconds | Coordinated execution |

---

## IP Classification Guide

For each source IP found in logs, classify as:

| Type | Characteristics | Source |
|------|----------------|--------|
| **Attacker external** | Non-RFC1918, unexpected geography, IDC/VPN ASN | FW logs, Windows Security |
| **Attacker pivot** | RFC1918 internal IP that's not a known workstation | Windows Security Type 3 |
| **VPN exit node** | AS with "VPN", "hosting", "datacenter" in name | ASN lookup |
| **TOR exit** | Listed in TOR exit node databases | Check against dan.me.uk/torlist |
| **Legitimate** | Office IP, known admin workstation, server | Confirm from client |

**Known attacker-friendly ASNs (non-exhaustive):**
```
AS34109  Serverius  (Netherlands) — frequently used VPN/proxy
AS29551  Airnet Group (Germany) — IDC hosting
AS262621 Cogent/Brazil DC — common South American attacker infra
AS20473  The Constant Company (US/EU) — VPS hosting
AS21219  DataGroup (Ukraine)
AS9009   M247 (multiple EU) — VPN and proxy
```
