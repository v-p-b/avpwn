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
