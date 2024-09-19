# Virtual Infosec Internal Penetration Test

Submitted by: Eshun Fiifi Assan  
To : Somuah 

## Table of Contents

  - Scope
  - Host Discovery
  - Service Discovery and Port Scanning
  - Vulnerability Scanning
  - Web-Based Attack Surfaces
  - Generating Payloads
  - CVSS v3.0 Reference Table


## Scope

The scope of engagement comprises of an internal network: 10.10.10.0/24 and a domain name: https://virtualinfosecafrica.com/

## Host Discovery
The port was scanned to check to see whether it is active.  

# Evidence 
![alt text](<Desktop/Screenshot 2024-09-19 at 1.04.09 PM.png>)


 For the domain provided in the Scope, subdomain enumeration was done using aiodnsbrute.
 ![alt text](<Desktop/Screenshot 2024-09-17 at 16.15.01.jpeg>)

## Service Discovery and Port Scanning

 The network hosts were scanned to determine which services are active for connections and saved to file as target.txt
 It revealed the specific host of that are running, which is critical for identifying known vulnerabilities.
  
## Evidence
![alt text](<Desktop/Screenshot 2024-09-17 at 3.14.58 PM.png>)


# Vulnerability Scanning
Vulnerability scanning is a crucial part of cybersecurity that involves systematically identifying and assessing weaknesses in systems, applications, and networks. It's like a security checkup for your digital assets, helping you understand potential risks and take steps to mitigate them.

- Assuming you have to develop your own custom wordlist, demonstrate how you will go about that using cewl. Describe situations when it will be needed to
- Show the procedure used during scanning of the vulnerabilities associated with these services
- Take screenshots of revelant commands to support your descriptions.


## Evidence
![alt text](<Desktop/Screenshot 2024-09-17 at 3.29.27 PM.png>)

- The file saved as target.txt under service discovery was scan for vulnerabilities with the Metasploit Auxilliary module.
## Evidence
VNC
![alt text](<Desktop/Screenshot 2024-09-17 at 4.10.09 PM.png>)
my SQL
![alt text](<Desktop/Screenshot 2024-09-17 at 3.58.57 PM.png>)


After using resources like Exploitdb and MITRE CVE to identify relevant vulnerabilities associated with the services in the network. These are the vulnerabilities that were found;
-CVE-2017-9805: This vulnerability allows attackers to bypass authentication and gain access to restricted areas of a web server. It affects versions 2.4.17 to 2.4.29.

Solution:
The most effective way to mitigate CVE-2017-9805 is to upgrade Apache HTTP Server to a patched version. Apache released patches for this vulnerability in versions 2.4.30 and later.


-CVE-2017-15715: This vulnerability allows attackers to execute arbitrary code on a web server by exploiting a flaw in the mod_cgi module. It affects versions 2.4.0 to 2.4.29.


Solution:
The most effective way to mitigate CVE-2017-15715 is to upgrade Apache HTTP Server to a patched version. Apache released patches for this vulnerability in versions 2.4.30 and later.



## Evidence
![alt text](<Desktop/Screenshot 2024-09-17 at 3.52.57 PM.png>)
![alt text](<Desktop/Screenshot 2024-09-17 at 3.57.09 PM.png>)

# Web-Based Attack Surfaces

- Now, using your http/https hosts file, use eyewitness to show the command and options that you will use to open the links and take screenshots of the web servers. Include options for eyewitness to load non-standard http/https ports.

# Evidence 
![alt text](<Desktop/Screenshot 2024-09-17 at 3.37.00 PM.png>)
![alt text](<Desktop/Screenshot 2024-09-17 at 3.41.12 PM.png>)


# Generating Payloads
- Now, assuming host 10.10.10.55 runs an Apache Tomcat web server(Java based), explain how you will use msfvenom to generate a payload that can trigger a TCP bind shell when executed by an attacker.
![alt text](<Desktop/Screenshot 2024-09-17 at 3.22.05 PM.png>)

- Do same for host 10.10.10.30 with the assumption it is running a Python server that can execute base64 encoded payloads.
![alt text](<Desktop/Screenshot 2024-09-17 at 3.32.34 PM.png>)
---

## CVSS v3.0 Reference Table
| Qualitative Rating | CVSS Score   |
|--------------------|--------------|
| None/Informational | N/A          |
| Low                | 0.1 – 3.9    |
| Medium             | 4.0 – 6.9    |
| High               | 7.0 – 8.9    |
| Critical           | 9.0 – 10.0   |
