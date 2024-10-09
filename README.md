# Cyber Security Tools

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A list of cyber security tools that you can use for both red and blue teaming.

## Table of Contents

- [Security Frameworks](#security-frameworks)
- [Red Teaming](#red-teaming)
  - [Web Application Pentesting](#web-application-pentesting)
  - [Network Pentesting](#network-pentesting)
  - [Mobile Application Pentesting](#mobile-application-pentesting)
  - [Physical Pentesting](#physical-pentesting)
  - [Adversary Simulation (Red Teaming)](#adversary-simulation)
  - [Social Engineering](#social-engineering)
- [Blue Teaming](#blue-teaming)
  - [Network Security](#network-security)
  - [Software Security](#software-security)
  - [Incident Response](#incident-response)
  - [Threat Hunting](#threat-hunting)
  - [Vulnerability Management](#vulnerability-management)
  - [SOC Management](#soc-management)
  - [Log and Data Analysis](#log-analysis)
  - [Security Policy and Compliance](#security-policy)
  - [User Awareness and Training](#user-awareness-)

## Red Teaming

### Penetration Testing

#### Web Application Pentesting

##### 1. Reconnaisance

- [Recon-ng](https://github.com/lanmaster53/recon-ng) - A web reconnaissance framework that provides a powerful environment for open-source web-based reconnaissance.
- [Google Dorking](https://www.exploit-db.com/google-hacking-database) - A technique that uses advanced Google search operators to find sensitive information exposed on the web.

###### 2. Scanning & Enumeration

- [Burpsuite](https://portswigger.net/burp) - A popular web application security testing tool that includes features for scanning, crawling, and analyzing web applications.
- [OWASP ZAP](https://www.zaproxy.org/) - An open-source web application security scanner that helps find security vulnerabilities in web applications.
- [Nikto](https://github.com/sullo/nikto) - A web server scanner that performs comprehensive tests against web servers for multiple items, including outdated server software, and vulnerabilities.
- [Acunetics](https://www.acunetix.com/) - An automated web application security scanner that checks for vulnerabilities like SQL injection, XSS, and more.

###### 3. Gaining Access / Exploitation

- [SQLMap](https://sqlmap.org/) - An open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities.
- [XSSer](https://github.com/epsylon/xsser) - a tool to exploit XSS vulnerabilities.
- [Burpsuite (Intruder)](https://portswigger.net/burp) - Besides scanning, Burp's Intruder tool can be used for brute-forcing and payload injection.
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - A popular password-cracking tool used for conducting rapid dictionary attacks against various protocols.
- [BeEF](https://beefproject.com/) - a powerful tool that can perform various tasks aimed at exploiting vulnerabilities in web browsers.

#### Network Pentesting

##### 1. Reconnaisance

- [Maltego](https://www.maltego.com/) - A tool for open-source intelligence (OSINT) and forensics that can visualize relationships between data.
- [Harvester](https://github.com/laramies/theHarvester) - A tool used for gathering e-mail accounts and subdomain names from different public sources (search engines, pgp key servers).
- [DNSRecon](https://github.com/darkoperator/dnsrecon) - A DNS reconnaissance tool that performs various DNS enumeration techniques.

###### 2. Scanning & Enumeration

- [Nmap](https://nmap.org/) - A powerful network scanner used for discovering hosts and services on a computer network.
- [Nessus](https://www.tenable.com/products/nessus) - A widely used vulnerability scanner that identifies vulnerabilities in systems and applications.
- [Wireshark](https://www.wireshark.org/) - A network protocol analyzer that captures and analyzes network traffic, useful for troubleshooting and identifying vulnerabilities.

###### 3. Gaining Access / Exploitation

- [Metasploit](https://www.metasploit.com/) - A widely used penetration testing framework that includes a range of exploits and payloads to gain access to systems.
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - A fast network logon cracker that supports numerous protocols for password guessing.
- [Aircrack-ng](https://www.aircrack-ng.org/) - A suite of tools for assessing Wi-Fi network security, including capturing packets and cracking WEP/WPA/WPA2 keys.

###### 4. Maintaining Access

- [Netcat](https://nmap.org/ncat/) - A networking utility that can create TCP/UDP connections and is often used for creating backdoors.
- [Meterpreter](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter.html) - A payload within Metasploit that allows for post-exploitation, providing a command shell and extensive features for maintaining access.
- [Empire](https://www.alpinesecurity.com/blog/empire-a-powershell-post-exploitation-tool/) - A post-exploitation framework that uses PowerShell agents for persistence and control.
- [Cobalt Strike](https://www.cobaltstrike.com/) - A commercial penetration testing tool that provides advanced features for post-exploitation and persistence.
- [RATs (Remote Access Trojans)](https://www.techtarget.com/searchsecurity/definition/RAT-remote-access-Trojan) - Tools like DarkComet or NjRAT allow attackers to maintain remote control over compromised systems.

###### 5. Clearing Tracks

- [CCleaner](https://www.ccleaner.com) - A tool used to remove unnecessary files and clear logs to cover tracks after an attack.
- [Metasploit (Clearing Logs / Post Exploitation Modules)](https://www.metasploit.com/) - Metasploit's post-exploitation modules can assist in clearing logs and covering tracks.
- [Timestomp](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/indicator-removal/timestomp) - A tool that allows users to modify file timestamps to obscure evidence of access or modification.
- [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - A collection of utilities (like PsExec) that can help manage and hide processes, as well as clear logs.
- [Rootkits](https://www.kaspersky.com/resource-center/definitions/what-is-rootkit) - Though illegal and unethical for legitimate pentesting, rootkits can hide files and processes from detection.