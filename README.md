AVPWN
=====

List of real-world threats against endpoint protection software - For future reference. The list is based on public information and thus is obviously incomplete. 

The list should include:
  * Non-public 0-day exploits at the time of reference
  * Public incidents where attackers exploited endpoint protection software 
  * Supporting public evidence should be provided for all records

The list doesn't include: 
  * Exploits intentionally disclosed to the vendor in any way (including full uncoordinated disclosure)
  * Detection bypasses, because I don't want to fill up the storage space of GitHub
  * Attacks or exploits against perimeter products, because I'm lazy

The List
--------

| Name                                                                        | Link                                                   | Internal ID | Server Side | Client Side | Known Incident |
|-----------------------------------------------------------------------------|--------------------------------------------------------|-------------|-------------|-------------|----------------|
| avast! Local Information Disclosure                                         | https://wikileaks.org/hackingteam/emails/emailid/45441 | 13-005      |           0 |           1 |       Brokered |
| avast! Local Privilege Escalation                                           | https://wikileaks.org/hackingteam/emails/emailid/45441 | 13-010      |           0 |           1 |       Brokered |
| McAfee ePolicy Orchestrator Privileged Remote Code Execution                | https://wikileaks.org/hackingteam/emails/emailid/45441 | 13-019      |           1 |           0 |       Brokered |
| McAfee ePolicy Orchestrator Post-Auth Privileged Remote Code Execution      | https://wikileaks.org/hackingteam/emails/emailid/45441 | 13-023      |           1 |           0 |       Brokered |
| McAfee ePolicy Orchestrator Post-Auth Privileged Remote Code Execution      | https://wikileaks.org/hackingteam/emails/emailid/45441 | 13-024      |           1 |           0 |       Brokered |
| ESET NOD32 Antivirus and ESET Smart Security Remote Pre-auth Code Execution | https://wikileaks.org/hackingteam/emails/emailid/45441 | 2010-0021   |           0 |           1 | Brokered, Sold |
| Symantec AntiVirus Remote Stack Buffer Overflow  | http://www.securityfocus.com/news/11426 | CVE-2006-2630   |           0 |           1 | Exploited ItW |
| McAfee Stinger Portable DLL Sideloading  | https://wikileaks.org/ciav7p1/cms/page_27492400.html | Fine Dining  |           0 |           1 | CIA collection |
| Sophos Virus Removal Tool DLL sideloading | https://wikileaks.org/ciav7p1/cms/page_27263043.html | Fine Dining  |           0 |           1 | CIA collection |
| Kaspersky TDSS Killer Portable DLL Sideloading | https://wikileaks.org/ciav7p1/cms/page_27492393.html | Fine Dining  |           0 |           1 | CIA collection |
| ClamWin Portable DLL Hijack | https://wikileaks.org/ciav7p1/cms/page_27262995.html | Fine Dining  |           0 |           1 | CIA collection |
| Kaspersky ?? SUID command injection | https://hackmd.io/s/r1gLMUUpx | evolvingstrategy  |           0 |           1 | EQGRP exploit leaked by Shadow Brokers  |
| Symantec rastlsc.exe DLL side-loading | https://www.welivesecurity.com/wp-content/uploads/2018/03/ESET_OceanLotus.pdf| OceanLotus | 0 | 1 | ESET report |

### Honorable mentions

* As of November 2016. Zerodium (a prominent vulnerability broker) [is offering](https://web.archive.org/web/20161108134847/http://zerodium.com/program.html) up to $40.000 for Antivirus LPE/RCE
  * In 2017. the price for AV LPE exploits [dropped](https://web.archive.org/web/20170823152044/https://zerodium.com/program.html) to $10.000 in 2017 (presumably because of the easy accessibility to such exploits). 
* In 2014. Kaspersky [reported](https://kasperskycontenthub.com/wp-content/uploads/sites/43/vlpdfs/unveilingthemask_v1.0.pdf) that the Careto malware was attempting to exploit a vulnerability in their products _"to make the malware 'invisible' in the system"_. The targeted vulnerability was fixed in 2008.
* In 2015. Kaspersky [reported](https://blog.kaspersky.co.uk/kaspersky-statement-duqu-attack/5858/) a compromise of their own systems. According to the report _"neither [Kaspersky's] products nor services have been compromised"_, and attackers were after information about _"ongoing investigations [...] detection methods and analysis capabilities"_. In 2017 [NYT reported](https://www.nytimes.com/2017/10/10/technology/kaspersky-lab-israel-russia-hacking.html) that Kaspersky was compromised by the Israeli intelligence that found that Russian services were using the companies infrastructure/products to "scour the world for U.S. secrets".
* In 2013. Bit9, a security firm mostly known for it's white-list based endpoint protection product, [was hacked](https://krebsonsecurity.com/2013/02/security-firm-bit9-hacked-used-to-spread-malware/) and code-signing certificates with private keys were stolen. With these, attackers were able to sign malware with Bit9's code-signing certificate. The signed malware was used to bypass Bit9 protection on the client.   
