#!/usr/bin/env python3
# -----------------------------------------
# TORRECON - Tor Onion Reconnaissance Tool
# Author: Educational / Defensive Security
# -----------------------------------------

import requests
import sys
from urllib.parse import urljoin

# -------- CONFIGURATION -------- #
TOR_PROXY = "socks5h://127.0.0.1:9050"
TIMEOUT = 25

PROXIES = {
    "http": TOR_PROXY,
    "https": TOR_PROXY
}

HEADERS = {
    "User-Agent": "torrecon/1.0 (Tor OSINT Recon)",
    "Accept": "*/*"
}

COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/graphql",
    "/rest",
    "/swagger",
    "/openapi.json",
    "/api/status"
]

# -------------------------------- #

def banner():
    print("""
               TORRECON-- 

        TOR ONION RECONNAISSANCE TOOL
    """)

def is_v3_onion(host):
    return host.endswith(".onion") and len(host.split(".")[0]) == 56

def check_online(url):
    try:
        r = requests.get(url, headers=HEADERS, proxies=PROXIES, timeout=TIMEOUT)
        return True, r
    except Exception as e:
        return False, str(e)

def detect_framework(headers, body):
    signatures = {
        "Flask": ["werkzeug", "flask"],
        "Django": ["django", "csrftoken"],
        "Express.js": ["express", "x-powered-by"],
        "PHP": ["php", "phpsessid"],
        "Laravel": ["laravel"],
        "Ruby on Rails": ["rails", "_rails_session"],
        "ASP.NET": ["asp.net"]
    }

    detected = []
    data = (str(headers) + body).lower()

    for fw, keys in signatures.items():
        for k in keys:
            if k in data:
                detected.append(fw)
                break

    return list(set(detected))

def detect_backend(headers):
    backend = []

    for v in headers.values():
        v = v.lower()
        if "php" in v:
            backend.append("PHP")
        if "python" in v:
            backend.append("Python")
        if "node" in v:
            backend.append("Node.js")
        if "ruby" in v:
            backend.append("Ruby")
        if "java" in v:
            backend.append("Java")

    return list(set(backend))

def tor_protection(headers, body):
    protections = []

    if "captcha" in body.lower():
        protections.append("CAPTCHA")
    if "javascript" in body.lower():
        protections.append("JavaScript challenge")
    if "403" in body:
        protections.append("Tor rate-limit / access control")
    if "cf-ray" in headers:
        protections.append("Cloudflare detected")

    return protections

def find_apis(base_url):
    found = []

    for path in COMMON_API_PATHS:
        try:
            r = requests.get(base_url.rstrip("/") + path,
                             headers=HEADERS,
                             proxies=PROXIES,
                             timeout=TIMEOUT)
            if r.status_code in [200, 401, 403]:
                found.append(f"{path} → HTTP {r.status_code}")
        except:
            pass

    return found

def fetch_file(base_url, name):
    try:
        r = requests.get(urljoin(base_url, name),
                         headers=HEADERS,
                         proxies=PROXIES,
                         timeout=TIMEOUT)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

# ------------- MAIN ------------- #

def main():
    banner()

    if len(sys.argv) != 2:
        print("Usage: python torrecon.py http://example.onion")
        sys.exit(1)

    base_url = sys.argv[1]
    host = base_url.replace("http://", "").replace("https://", "").split("/")[0]

    print("[+] Target:", base_url)

    print("\n[*] Onion Version:")
    if is_v3_onion(host):
        print("    ✔ v3 onion service")
    else:
        print("    ⚠ v2 onion (DEPRECATED)")

    print("\n[*] Service Status:")
    online, result = check_online(base_url)
    if not online:
        print("    ✖ Offline:", result)
        sys.exit(0)

    print(f"    ✔ Online (HTTP {result.status_code})")

    headers = result.headers
    body = result.text

    print("\n[*] HTTP Headers:")
    for k, v in headers.items():
        print(f"    {k}: {v}")

    print("\n[*] Frameworks:")
    fw = detect_framework(headers, body)
    print("    " + (", ".join(fw) if fw else "Unknown"))

    print("\n[*] Backend Language:")
    backend = detect_backend(headers)
    print("    " + (", ".join(backend) if backend else "Unknown"))

    print("\n[*] Tor-aware Protections:")
    prot = tor_protection(headers, body)
    print("    " + (", ".join(prot) if prot else "None detected"))

    print("\n[*] API Endpoints:")
    apis = find_apis(base_url)
    if apis:
        for a in apis:
            print("    " + a)
    else:
        print("    None found")

    print("\n[*] robots.txt:")
    robots = fetch_file(base_url, "/robots.txt")
    print(robots if robots else "    Not found")

    print("\n[*] sitemap.xml:")
    sitemap = fetch_file(base_url, "/sitemap.xml")
    print(sitemap if sitemap else "    Not found")

    print("\n[✓] TORRECON scan completed\n")

if __name__ == "__main__":
    main()
