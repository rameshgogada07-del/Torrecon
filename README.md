# Torrec# 🧅 TORRECON  
### Tor Onion Reconnaissance Tool

TORRECON is a **passive reconnaissance tool** designed specifically for **Tor (.onion) services**.  
It helps security researchers, learners, and defenders understand the **technology stack and behavior of onion websites** without performing intrusive or illegal actions.

The tool works entirely over the **Tor network** and focuses on **OSINT-style information gathering**.

---

## 📖 About TORRECON

TORRECON analyzes a given `.onion` service and provides useful metadata such as:

- Whether the onion service is **online or offline**
- Whether it is a **v2 or v3 onion service** (v2 is deprecated)
- What **frameworks and backend technologies** might be in use
- Presence of **API endpoints**
- Detection of **Tor-aware protections** like CAPTCHA or JavaScript challenges

⚠️ TORRECON is **non-intrusive** and does **not exploit vulnerabilities**.

---

## ✨ Features

- ✅ Onion service **availability check**
- ✅ **v2 vs v3 onion** detection
- ✅ Web **framework identification**
  - Flask
  - Django
  - Express.js
  - PHP / Laravel
  - Ruby on Rails
  - ASP.NET
- ✅ **Backend language detection** (heuristic-based)
- ✅ HTTP **response header analysis**
- ✅ **Common API endpoint discovery**
- ✅ Fetches:
  - `robots.txt`
  - `sitemap.xml`
- ✅ Detects **Tor-aware protections**
  - CAPTCHA
  - JavaScript challenges
  - Access restrictions
- ✅ Runs fully through **Tor SOCKS proxy**

---

## 🛠 Requirements

### 1️⃣ Python
- **Python 3.8 or higher**
- Tested with Python **3.10 – 3.13**

Check your version:
```bash
python --version

Install required libraries:
pip install requests[socks] beautifulsoup4

Installation
git clone https://github.com/yourusername/torrecon.git
cd torrecon

Project structure:
torrecon/
 ├── torrecon.py
 └── README.md

Running TORRECON (Step-by-Step)
Step 1: Start Tor

Make sure Tor is running locally.

Step 2: Run the tool

Provide a valid .onion URL as an argument:
python torrecon.py http://exampleonionaddress.onion

Output
Onion Version
Service Status
HTTP Headers
Framework Detection
Backend Language
Tor-aware Protections
API Endpoints
robots.txt & sitemap.xml

Configuration
TOR_PROXY = "socks5h://127.0.0.1:9050"

👨‍💻 Developer

Ramesh Gogada

Cybersecurity & OSINT Enthusiast





  
