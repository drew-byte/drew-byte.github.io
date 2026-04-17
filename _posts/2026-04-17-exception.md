---
title: Exception Writeup - Hack Smarter Lab
description: NoSQL Injection to RCE via Rocket.Chat CVE-2021-22911
author: drewbyte
date: 2026-04-17 00:00:00 +0800
categories: [writeup, lab]
tags: [writeup, lab]
pin: false
---

> **Description**
{: .box-danger }

A walkthrough of the Exception lab challenge, where an exposed Rocket.Chat instance is exploited through a NoSQL injection vulnerability (CVE-2021-22911) to achieve remote code execution. This write-up covers reconnaissance with Nmap, service discovery, abuse of password reset functionality, token extraction via injection, and privilege escalation to root.

---

### Reconnaissance

I saw that there were 2 open ports on the target, which are SSH and HTTP.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -A -sC -sV -p- 10.1.228.158 -T4
```

So I navigated to the HTTP service and explored the target.

![exception](/assets/img/exception1.png){: .mx-auto .shadow .rounded-10 w="800" }

I checked the source code and found something interesting.

![exception](/assets/img/exception2.png){: .mx-auto .shadow .rounded-10 w="800" }

There might be a logic flow here that I need to check.

![exception](/assets/img/exception3.png){: .mx-auto .shadow .rounded-10 w="800" }

It looks like a red herring, so I decided to run another Nmap scan.

The command I used for scanning is below:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -A -sC -sV -p- 10.1.228.158 -T4
```

Now I will visit the target on port 3000, and I found a Rocket.Chat instance.

---

### Initial Access

I registered a low-privileged account on the Rocket.Chat instance with the credentials `drewbyte-1:password` to enumerate from within.

Inside the general channel, I found a user named `localh0ste` who had leaked their email address in chat.

![exception](/assets/img/exception4.png){: .mx-auto .shadow .rounded-10 w="800" }

``localh0ste@exception.local``

While browsing, I intercepted requests with **Burp Suite** and noticed API calls in the background. I checked the version endpoint.

![exception](/assets/img/exception5.png){: .mx-auto .shadow .rounded-10 w="800" }

http://10.1.228.158:3000/api/info

I saw that there was an API running in the background, so I checked the version.

![exception](/assets/img/exception6.png){: .mx-auto .shadow .rounded-10 w="800" }

After checking the version of Rocket.Chat, I found that it is vulnerable to NoSQL injection leading to RCE.

![exception](/assets/img/exception7.png){: .mx-auto .shadow .rounded-10 w="800" }

---

### Exploitation

After confirming the vulnerability and getting the Exploit-DB ID, I downloaded it using searchsploit.

![exception](/assets/img/exception8.png){: .mx-auto .shadow .rounded-10 w="800" }

I then used the exploit with the following command:

```bash
┌──(kali㉿kali)-[~]
└─$ python3 50108.py \
  -u test@exception.local \
  -a localh0ste@exception.local \
  -t http://10.1.228.158:3000
```

While doing this and waiting for the password reset, I set up a listener.

![exception](/assets/img/exception9.png){: .mx-auto .shadow .rounded-10 w="800" }

The script took too long, which caused the token to expire.

![exception](/assets/img/exception10.png){: .mx-auto .shadow .rounded-10 w="800" }

### Exploit Modification

I tried to modify the code with the help of AI.

After that, I converted the 2FA secret into a numeric code using oathtool:

```bash
┌──(kali㉿kali)-[~]
└─$ echo "KIYTUQZKO4YD6ZJYEUWFAMB4OBAU6I3RJBCXMP3UGJHEOOBJGNLQ" | oathtool --totp -b -
915594
```

![exception](/assets/img/exception11.png){: .mx-auto .shadow .rounded-10 w="800" }

After getting the 2FA code, I tried to log in with it, and it worked.

![exception](/assets/img/exception12.png){: .mx-auto .shadow .rounded-10 w="800" }

### Remote Code Execution

After investigating the admin panel, I checked the integrations section and found two RCE-related entries.

![exception](/assets/img/exception13.png){: .mx-auto .shadow .rounded-10 w="800" }

There was a webhook URL created by the script. I converted the base64 payload to a text file.

![exception](/assets/img/exception14.png){: .mx-auto .shadow .rounded-10 w="800" }

And yes, it came from the script that was generated earlier.

![exception](/assets/img/exception15.png){: .mx-auto .shadow .rounded-10 w="800" }

To trigger it, I saved it first and used curl on the webhook:

``http://ip:3000/hooks/token``

But before that, I created a listener on port 4446.

![exception](/assets/img/exception16.png){: .mx-auto .shadow .rounded-10 w="800" }

After triggering it, I got a shell.

I checked the home directory and saw only one user, which is node.

![exception](/assets/img/exception17.png){: .mx-auto .shadow .rounded-10 w="800" }

### Privilege Escalation

I didn’t find anything interesting at first, so I continued enumerating for credentials that I could use for SSH login.

![exception](/assets/img/exception18.png){: .mx-auto .shadow .rounded-10 w="800" }

There was a file named Backup_db.txt in the home directory, and I found credentials inside it. I tried using them for SSH, and it worked.

![exception](/assets/img/exception19.png){: .mx-auto .shadow .rounded-10 w="800" }

For root privilege escalation, I found something interesting after running:

``sudo -l``

![exception](/assets/img/exception20.png){: .mx-auto .shadow .rounded-10 w="800" }

I tried running the command:

``sudo /opt/log_inspector/check_log --clean``

After that, I pressed:

```
CTRL+R
CTRL+X
```

![exception](/assets/img/exception21.png){: .mx-auto .shadow .rounded-10 w="800" }

Then I inserted the following command:

reset; sh 1>&0 2>&0

![exception](/assets/img/exception22.png){: .mx-auto .shadow .rounded-10 w="800" }

And it worked!

![exception](/assets/img/exception23.png){: .mx-auto .shadow .rounded-10 w="800" }