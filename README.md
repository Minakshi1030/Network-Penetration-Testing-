🔐 Network Penetration Testing with Real-World Exploits & Remediation

🎯 Project Objectives

Simulate real-world penetration testing in a controlled lab environment using **Kali Linux (attacker) and Metasploitable VM (target).


Key Phases:**

* Scanning
* Reconnaissance
* Enumeration
* Exploitation
* Privilege Escalation
* Password Cracking
* Remediation

---

📘 Introduction

Penetration testing (Ethical Hacking) helps identify and patch vulnerabilities before attackers can exploit them. This project involves using industry-standard tools like **Nmap**, **Metasploit**, and **John the Ripper** to discover and exploit weaknesses in a test environment.

---

⚙️ Tools & Setup

| Tool                     | Description                            |
| ------------------------ | -------------------------------------- |
| **Kali Linux**           | Attacker machine with pentesting tools |
| **Metasploitable**       | Intentionally vulnerable VM            |
| **Nmap**                 | Port scanning and service detection    |
| **Metasploit Framework** | Exploitation tool                      |
| **John the Ripper**      | Password cracking                      |
| **Netcat**               | Network utility                        |
| **VirtualBox/VMware**    | VM hosting                             |

---

🔍 Phases & Tasks

1️⃣ Scanning

* Basic Scan:** `nmap -v 192.168.160.131`
* Full Port Scan:** `nmap -v -p- 192.168.160.131`
* Service Detection:** `nmap -sV 192.168.160.131`
* OS Detection:** `nmap -O 192.168.160.131`

2️⃣ Reconnaissance

Identified **7 hidden ports** including:

```
8787, 36588, 53204, 53452, 59437, 3632, 6697
```

3️⃣ Enumeration

* OS: Linux 2.6.9 – 2.6.33
  
* Open Ports & Services:**

  * `21/tcp`: vsftpd 2.3.4
  * `22/tcp`: OpenSSH 4.7p1
  * `80/tcp`: Apache 2.2.8
  * `3306/tcp`: MySQL 5.0.51a
  * ...and more (Full list in repo)

4️⃣ Exploitation

✅ Exploited:

* FTP (vsftpd 2.3.4):

  ```
  exploit/unix/ftp/vsftpd_234_backdoor
  ```
* Samba SMB:

  ```
  exploit/multi/samba/usermap_script
  ```
* R Services (rlogin):

  ```
  rlogin -l root 192.168.160.131
  ```

5️⃣ Privilege Escalation

Created new user:

```bash
adduser minakshi
password: hello
usermod -aG sudo minakshi
```

6️⃣ Password Cracking

Used John the Ripper:

```bash
john minakshi_hash.txt
john minakshi_hash.txt --show
```

7️⃣ Remediation Suggestions

| Vulnerable Service   | CVE           | Fix                                 |
| -------------------- | ------------- | ----------------------------------- |
|   vsftpd 2.3.4       | CVE-2011-2523 | Upgrade to v3.0.5 or switch to SFTP |
|   Samba 3.0.20       | CVE-2007-2442 | Upgrade to 4.20.1, disable SMBv1    |
|   rlogin/rsh/rexec   | CVE-1999-0651 | Disable & use SSH instead           |

---

🧠 Major Learnings

✅ Hands-on with Kali tools: Nmap, Metasploit, John

✅ Understood user creation, privilege escalation, and hash cracking 

✅ Learned to analyze outdated services & apply real-world security fixes

✅ Practiced ethical hacking with responsible disclosure mindset

---

📂 Repository Structure

```
/project
├── scans/
│   ├── full_scan.txt
│   ├── os_detection.txt
├── exploits/
│   ├── ftp_backdoor.md
│   ├── smb_usermap.md
├── creds/
│   ├── minakshi_hash.txt
│   ├── cracked_password.txt
├── remediation/
│   ├── vsftpd_patch.md
│   ├── samba_hardening.md
└── README.md
```

---

💡 Conclusion

This project provides a complete hands-on experience in network penetration testing. It helps in understanding the attacker's mindset, common vulnerabilities, and how to secure systems proactively.

---

