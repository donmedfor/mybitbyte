# CRTA — Certified Red Team Analyst

**Provider:** CyberWarFare Labs (CWL)  
**Status:** ✅ Passed  
**Focus:** Red Teaming / Active Directory Attack Chains

## Overview

CRTA is an entry-level red team certification offered by **CyberWarFare Labs**. The exam is entirely practical—there are no multiple-choice questions. You must compromise a simulated enterprise environment by completing a full attack chain within a time limit.

It is designed to help learners transition from CTF or blue team roles into red teaming. Unlike certifications that rely on multiple-choice theory, CRTA requires you to actually perform the intrusion. It bridges the gap between theoretical knowledge and real-world offensive operations.

## Exam Format

| Item | Details |
|---|---|
| Provider | CyberWarFare Labs (CWL) |
| Difficulty | Beginner to intermediate |
| Exam format | Fully hands-on, black-box |
| Exam duration | 6 hours (flag-based; no report submission required) |
| Prerequisites | Basic penetration testing skills + comfort with the command line |

The exam is delivered via a **live VPN-connected environment**. Your goal is to complete a multi-stage attack and capture flags placed throughout the environment within the allotted time. The final objective is to retrieve a specific file from the Domain Controller's Administrator Desktop.

There are no theoretical questions—you either compromise the targets or you don't pass. The entire engagement mirrors a real red team assessment: starting with external reconnaissance, gaining initial access, escalating privileges, moving laterally, and ultimately controlling high-value targets in the domain.

## Network & VPN Setup

### VPN Connection

The lab is accessed via an **OpenVPN configuration file (`.ovpn`)** provided after purchasing the exam. This file and the associated credentials are typically sent to you **about 30 minutes before your scheduled exam time**.

**Connection Steps:**
1. **Import the `.ovpn` file** into your preferred virtual environment (such as VMware Workstation or VirtualBox).
2. **Connect** to establish the VPN tunnel. No manual configuration is required.

Once connected, you are assigned a **VPN IP address** on the examination network (e.g., `172.26.10.x`), which serves as your foothold from which all attacks originate.

### Exam Network Topology

The VPN tunnel grants **direct access to both network segments** — no pivoting is required. You can reach the external scope and the internal `10.10.10.0/24` range straight from your attacking machine.

<img width="1536" height="1024" alt="Layered Network Attack Path Diagram" src="https://github.com/user-attachments/assets/a3f18f38-0e76-467a-81de-56a35630fe2f" />

### Network Scope Summary

| Segment | Range | Notes |
|---|---|---|
| VPN Scope | `172.26.10.0/24` | Directly reachable after connecting |
| Out of Scope | `172.26.10.1` | Gateway — **do not touch** |
| Initial Target | `172.26.10.11` | Externally exposed host (initial foothold) |
| Internal Network | `10.10.10.0/24` | Directly reachable via VPN (no pivot needed) |
| Domain Controller | `10.10.10.100` | Final high-value target |

### Environment Reset

The lab environment **resets automatically every 24 hours** to ensure stability. This means any changes you make to the machines (e.g., creating users, modifying configurations) will be reverted, so you must plan your attack chain accordingly and avoid relying on persistent modifications.

### Practical Considerations

- Ensure your **internet connection is stable** at least one hour before the exam, as connectivity issues can be frustrating and disruptive.
- The lab is a **shared environment** among all students, so if another candidate misconfigures a machine, you may need to contact support and wait for a reset.
- You will need to install and configure your own **attacking machine** (typically Kali Linux) with the tools you plan to use before connecting to the VPN.

## Core Skill Areas

CRTA focuses on **enterprise Active Directory environments**. The key domains covered include:

**Red Team Methodology & C2 Frameworks**  
Understanding the overall red team workflow and adversary simulation mindset, plus familiarity with command-and-control frameworks.

**External & Internal Attack Operations**  
Enumerating and exploiting externally exposed services, then continuing attacks once inside the internal network.

**Active Directory Enumeration & Attacks**  
This is the heart of CRTA: AD infrastructure enumeration, Kerberos-related attacks (including Golden Ticket and Silver Ticket techniques), privilege escalation, and lateral movement.

**Credential Harvesting & Post-Exploitation**  
Extracting credentials from memory or configuration (LSA dumps, Secretsdump, etc.), using them to expand access, and maintaining persistence.

## Attack Chain Walkthrough (My Experience)

The exam follows a clear chain: **external foothold → Linux privilege escalation → credential discovery → lateral movement to AD → DC compromise**. Below is how my run unfolded.

### Phase 1 — Initial Foothold via LFI

Enumerating the externally exposed host `172.26.10.11`, I found a web application vulnerable to **Local File Inclusion (LFI)**. Reading `/etc/passwd` confirmed the vulnerability and revealed the list of local users. Checking other common files, I located a set of **user credentials** on the box — likely from a config or backup file.

### Phase 2 — SSH Access & Linux Privilege Escalation

With the recovered credentials, I **SSH'd into the Linux machine** and began standard post-exploitation enumeration (`id`, `sudo -l`, SUID binaries, world-writable files, cron jobs).

`sudo -l` showed I could run **`vi` as root** — a classic GTFOBins misconfiguration. Escaping the editor's shell gave me a root shell on the box.

### Phase 3 — Pivoting into Containers & Discovering Domain Creds

As root, I ran `docker ps` and found **two running containers**:

- a **Node.js application**
- a **Python server**

Both exposed services I could reach from the host. Enumerating the Node.js app, I discovered another **LFI** — this time inside the container. Reading files through it, I found a configuration file containing **domain credentials** (a valid AD account).

### Phase 4 — Discovering the Domain Controller

Still hunting for internal context, I checked `/var/log/auth.log`. It contained **SSH attempts from an unfamiliar internal IP** — which matched the shape of a **Domain Controller**. Using the domain credentials I had just recovered, I authenticated successfully against that host.

### Phase 5 — AD Enumeration with BloodHound

With valid domain credentials in hand, I ran **BloodHound** to map the environment.

The output showed my user was a member of the **Backup Operators** group — a high-impact finding. Members of this group effectively hold **`SeBackupPrivilege`** on domain-joined machines, which bypasses normal file ACLs.

### Phase 6 — Backup Operators → LSA Dump → Domain Compromise

Abusing `SeBackupPrivilege`, I performed the classic **Backup Operators attack**:

1. Enabled `SeBackupPrivilege` in my session.
2. Used **`diskshadow`** (or an equivalent shadow-copy technique) to snapshot the target volume.
3. Copied the **SAM**, **SYSTEM**, and **SECURITY** registry hives out of the shadow copy.
4. Ran **`secretsdump.py`** against the dumped hives to extract **LSA secrets and local hashes**.

This yielded local administrator credentials that unlocked further access. From there, the chain continued to the **Domain Controller at `10.10.10.100`**, where I retrieved the objective file on the Administrator's Desktop.

## Preparation Strategy

**1. Build a solid AD foundation first**

Before booking the exam, make sure you can independently perform AD enumeration, privilege escalation, and lateral movement. Practice with TryHackMe's AD rooms (Breaching AD, Attacking Kerberos, Exploiting AD, etc.) and Hack The Box retired machines or Pro Labs.

**2. Enumeration is everything**

Multiple successful candidates emphasize that **about 80% of exam time should be spent on enumeration**. Don't rush to use tools—systematically read every clue, build a complete map of the environment, and then decide on your attack path.

**3. Know the tools but don't rely on them**

Tools you should be comfortable with include: enumeration tools like nmap, BloodHound, PowerView; and AD attack tools like Impacket, CrackMapExec, Rubeus. But understanding **native commands** (e.g., `whoami`, `net group`, `nltest`) is equally important—stealth often favors built-in methods over noisy tools.

**4. Practice full attack chain thinking**

CRTA tests your ability to link **initial access to domain control**, not just exploit a single vulnerability. Train yourself to think in chains: how does each piece of information create the next opportunity?

**5. Time management and mindset**

Six hours feels short during the actual exam. Practice **time-boxing** each phase: finish reconnaissance and initial access first, then focus on internal network and AD. When you hit a wall, take a short break and revisit existing information with fresh eyes—that's usually more effective than blind attempts.

**6. Prepare your environment ahead of time**

Install and configure your attacking machine with all the tools you plan to use **before** the exam day. Test your VPN connection and ensure your internet is stable.

## Key Takeaways

- **LFI chains can go deep.** A single LFI on the external host led to `/etc/passwd`, then credentials, then SSH, then root, then containers, then domain creds. Always keep reading files — the next link in the chain is often one directory away.
- **`sudo -l` should be the first thing you run** on any Linux box. A GTFOBins-eligible binary (`vi`, `find`, `less`, etc.) is a free root shell.
- **Containers are not a boundary.** Once you're root on the host, `docker ps` is reconnaissance — internal services often hold secrets the host doesn't.
- **`/var/log/auth.log` is underrated.** Failed SSH attempts from internal IPs are a strong hint at the AD environment's location.
- **BloodHound is non-negotiable.** It's how you spot group memberships (like `Backup Operators`) that turn a low-privilege user into a domain-level threat.
- **`Backup Operators` = `SeBackupPrivilege` = game over.** Memorize the diskshadow → hives → `secretsdump` chain before the exam.

## Overall Assessment

CRTA offers good **value for money** among entry-level red team certifications. It's especially suited for practitioners who already have some penetration testing background and want to systematically learn Active Directory attack chains. The course includes 30 days of lab access and covers the full flow from external reconnaissance to domain controller compromise.

However, CRTA is not for complete beginners. If you're not yet comfortable with Windows/Linux command line, networking fundamentals, and AD concepts, build that foundation first through TryHackMe or Hack The Box before considering this certification.

---

<p><a href="#" data-page="overview">← Back to Certifications</a></p>
