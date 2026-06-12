# Syntecxhub_Port_Scanner


# Syntecxhub Cybersecurity Internship
### Week 1 Projects — Hariom Patidar

This repository contains my submissions for the **Syntecxhub Cybersecurity Internship Program**, Week 1.  
Both projects are written in Python and focus on core cybersecurity concepts — network scanning and encrypted credential storage.

---

## 📁 Repository Structure

```
Syntecxhub_CyberSecurity/
│
├── project1_port_scanner/
│   ├── port_scanner.py       # Main script
│   └── requirements.txt      # No external dependencies needed
│
├── project2_password_manager/
│   ├── password_manager.py   # Main script
│   └── requirements.txt      # cryptography library
│
└── README.md
```

---

## Project 1 — TCP Port Scanner

### What it does
A multithreaded TCP port scanner that connects to a target host and checks which ports are open. It identifies the service running on each open port and saves results to a log file.

### Concepts covered
- **Socket programming** — using Python's `socket` module for TCP connections
- **Multithreading** — scanning multiple ports simultaneously using `threading`
- **Exception handling** — handles timeouts, refused connections, DNS errors
- **File I/O** — saves scan results to a timestamped `.txt` log file

### How to run

```bash
cd project1_port_scanner
python port_scanner.py
```

No external libraries needed — only Python standard library.

### Sample output

```
==================================================
       TCP PORT SCANNER
  Syntecxhub Internship | Week 1 Project 1
  Author: Hariom Patidar
==================================================

  Enter target IP or hostname: scanme.nmap.org

  Select port range to scan:
  [1] Common ports only
  [2] Well-known ports (1 - 1024)
  [3] Full scan (1 - 65535)

  Your choice: 1

  Starting scan on: 45.33.32.156
  Total ports to scan: 16
  Scan started at: 14:32:10

---------------------------------------------
  OPEN PORTS FOUND:
---------------------------------------------
  [OPEN]  Port    22  -->  SSH
  [OPEN]  Port    80  -->  HTTP

==================================================
  SCAN SUMMARY
==================================================
  Target       : 45.33.32.156
  Ports Scanned: 16
  Open Ports   : 2
  Time Taken   : 4 seconds
  Open List    : [22, 80]
==================================================
```

---

## Project 2 — Local Password Manager (VaultPy)

### What it does
A command-line password manager that stores credentials encrypted on disk. Uses AES-256 encryption via PBKDF2 key derivation from a master password. The vault is saved as an encrypted file that cannot be read without the correct master password.

### Concepts covered
- **AES-256 encryption** — via Python's `cryptography` library (Fernet)
- **PBKDF2 key derivation** — master password → encryption key (480,000 iterations)
- **Secure storage** — master password is never stored anywhere on disk
- **CRUD operations** — add, retrieve, delete, and search password entries
- **Random salt** — ensures unique keys even if two users share the same master password

### Security design

| What | How |
|---|---|
| Encryption | AES-256 (Fernet) |
| Key derivation | PBKDF2-HMAC-SHA256, 480,000 iterations |
| Salt | 16 random bytes, stored in `vault.salt` |
| Master password | Never stored — only used to derive key in memory |
| Vault file | `vault.enc` — unreadable without master password |

### How to run

```bash
cd project2_password_manager

# Install dependency
pip install -r requirements.txt

# Run the program
python password_manager.py
```

### Sample output

```
=============================================
  VaultPy — Local Password Manager
  Syntecxhub Internship | Week 1 Project 2
  Author: Hariom Patidar
=============================================

  [*] No vault found. Setting up a new one.
  Create master password : ********
  Confirm master password: ********
  [+] Vault created successfully!

  [+] Vault opened. 0 password(s) stored.

========================================
  VaultPy - Password Manager
========================================
  1. Add / Update password
  2. Get password
  3. Delete password
  4. Search passwords
  5. List all saved services
  6. Save and Exit
========================================
```

---

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.x | Primary language |
| `socket` | TCP connections for port scanner |
| `threading` | Parallel port scanning |
| `cryptography` | AES-256 encryption for password manager |

---

## Author

**Hariom Patidar**  
Cybersecurity Intern @ Syntecxhub  
[LinkedIn](#) | [GitHub](#)

---

> ⚠️ **Ethical Notice:** The port scanner is intended for educational purposes only.  
> Only scan systems you own or have explicit permission to test.  
> Unauthorized scanning is illegal under the IT Act 2000 (India).
