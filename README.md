# 🕷️ FuzzScrape v4 - Fear Edition by FrontManX1 🇮🇩

## ⚔️ Terminal-Based Web Exploit Toolkit - NO ROOT NEEDED

**FuzzScrape** adalah toolkit eksploitasi web stealth, dirancang untuk bekerja 100% di Termux (Android), VPS, dan sistem tanpa root. Dibuat oleh FrontManX1 menggunakan HP, tanpa laptop, tanpa tim, dari 0.

---

## 🔥 FITUR UNGGULAN

- 🔗 Chain Mode: `admin ➝ brute ➝ upload ➝ shell ➝ beacon`
- 🔓 Bruteforce admin login
- 📂 Upload shell + auto trigger RCE
- 🧠 XSS & SQLi Payload Mutator anti-WAF
- 🛰️ Beacon Mode (Command listener via HTTP)
- 🌐 Google Dork Scan
- 🔁 CLI interaktif & chaining otomatis
- 📱 Jalan di HP (Termux, Android no-root)
- 🧬 JA3 spoofing + delay randomizer
- 🔒 Keylock + self-destruct opsional
- 🧾 Output JSON & SQLite logging

---

## 📦 CARA INSTALASI (No Root - Termux / VPS)

```bash
git clone https://github.com/FrontManX1/fuzzscrapeV2.git
cd fuzzscrapeV2
chmod +x install.sh
./install.sh
python3 fuzzscrape.py