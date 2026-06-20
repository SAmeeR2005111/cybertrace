# CyberTrace OSINT Suite v1.0

A powerful **OSINT (Open Source Intelligence)** toolkit built for cyber investigations and threat intelligence gathering.

```
╔═══════════════════════════════════════════════════════════════╗
║           CyberTrace OSINT Suite v1.0                        ║
║      Built for Cyber Cell Investigations                      ║
║      APCSIP-2026 | Amroha Police Cybersecurity               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## Features

CyberTrace includes **4 core investigation modules**:

### 🔍 Module 1: Username Hunt
- Search a username across **25+ social media platforms**
- Instantly identify where a user has accounts
- Platforms: Instagram, Twitter/X, GitHub, Reddit, TikTok, LinkedIn, YouTube, and more
- Generates detailed JSON report

### 📧 Module 2: Email/Phone Intelligence
- **Email validation** & analysis
- Detect disposable/temporary email providers
- **Phone number validation** (India-focused)
- Identify carrier & operator
- Check for suspicious patterns

### 🖼️ Module 3: Image OSINT
- Extract **EXIF metadata** from photos
- Recover **GPS coordinates** from images
- Extract camera make/model, date taken, and more
- Identify location via Google Maps links
- Privacy warning: Detect embedded location data

### 🌐 Module 4: Domain/IP Recon
- **IP geolocation** lookup
- **WHOIS** domain registration data
- **DNS records** (A, AAAA, MX, NS, TXT, CNAME, SOA)
- HTTP headers and security analysis
- Threat intelligence links (VirusTotal, Shodan, URLScan)

### ⚡ Module 5: Full Investigation
- Run **all modules** on a single target in one session
- Comprehensive combined report

---

## Installation

### Prerequisites
- **Python 3.7+**
- **pip** (Python package manager)

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/cybertrace.git
cd cybertrace
```

### Step 2: Create a Virtual Environment

```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux/macOS (Bash)
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `requests` — HTTP requests for username scanning
- `Pillow` — Image EXIF extraction
- `python-whois` — Domain WHOIS lookup
- `dnspython` — DNS record queries

---

## Quick Start

### Interactive Mode (Recommended for Beginners)

```bash
python cybertrace.py
```

This launches an interactive menu where you choose:
```
  [1] Username Hunt
  [2] Email/Phone Intel
  [3] Image OSINT
  [4] Domain/IP Recon
  [5] Full Investigation
  [0] Exit
```

Follow the prompts and save reports as JSON files.

---

## CLI Usage (Advanced)

Run investigations directly from the command line:

### 1. Username Hunt

```bash
python cybertrace.py username exampleuser
```

**Output:** `report_username_exampleuser.json`

### 2. Email / Phone Intelligence

```bash
# Email validation
python cybertrace.py email user@example.com

# Phone analysis (India format)
python cybertrace.py email 919473780326
```

**Output:** `report_email_user_at_example.com.json`

### 3. Image OSINT (EXIF & GPS Extraction)

```bash
python cybertrace.py image C:\path\to\photo.jpg
```

**Output:** `report_image_photo.jpg.json`

### 4. Domain / IP Reconnaissance

```bash
# Domain lookup
python cybertrace.py domain example.com

# IP geolocation
python cybertrace.py domain 1.1.1.1
```

**Output:** `report_domain_example.com.json`

---

## Report Output

All investigations generate **JSON reports** saved to the current directory:

```json
{
  "target": "exampleuser",
  "found": [
    {
      "platform": "Instagram",
      "url": "https://www.instagram.com/exampleuser"
    }
  ],
  "not_found": ["Reddit", "LinkedIn"],
  "timestamp": "2026-06-20 14:30:45.123456"
}
```

### Findings include:
- Matched platform URLs
- Non-matching platforms
- Metadata (timestamps, geolocation, DNS records, etc.)
- GPS coordinates (for images)
- WHOIS data (for domains)

---

## Examples

### Example 1: Find all accounts for a username

```bash
python cybertrace.py username john_doe
```

**What it does:**
- Checks Instagram, Twitter, GitHub, LinkedIn, etc.
- Returns all profiles found
- Saves results to JSON

### Example 2: Validate an email and check for breaches

```bash
python cybertrace.py email alice@gmail.com
```

**What it does:**
- Validates email format
- Detects if it's a disposable email
- Shows MX records (if `dnspython` installed)
- Provides link to HaveIBeenPwned for breach check

### Example 3: Extract GPS from a photo

```bash
python cybertrace.py image evidence.jpg
```

**What it does:**
- Reads EXIF metadata
- Extracts GPS coordinates
- Shows camera details
- Generates Google Maps link

### Example 4: Investigate a suspicious domain

```bash
python cybertrace.py domain suspicious-site.xyz
```

**What it does:**
- Resolves domain to IP
- Performs WHOIS lookup
- Fetches DNS records
- Shows geolocation
- Links to VirusTotal, Shodan, URLScan

---

## Requirements

### Installed Packages

- **requests** ≥ 2.0.0 — HTTP client for web requests
- **Pillow** ≥ 9.0.0 — Image processing and EXIF extraction
- **python-whois** ≥ 0.7 — WHOIS domain lookup
- **dnspython** ≥ 2.0.0 — DNS queries

### Optional (Manual)

- **HaveIBeenPwned API** — For breach checking (requires registration at haveibeenpwned.com)
- **Shodan API** — For advanced IP scanning (requires account at shodan.io)

---

## File Structure

```
cybertrace/
├── cybertrace.py          # Main application
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore rules
├── README.md             # This file
└── report_*.json         # Generated reports (ignored by git)
```

---

## Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'requests'`

**Solution:** Install dependencies again:
```bash
pip install -r requirements.txt
```

### Issue: EXIF data not showing for images

**Solution:** Image may have had metadata stripped. Try:
```bash
pip install --upgrade Pillow
```

### Issue: DNS lookups failing

**Solution:** Ensure `dnspython` is installed:
```bash
pip install dnspython
```

### Issue: WHOIS returns no data

**Solution:** The registry may not support lookups. Try with a different domain.

---

## Disclaimer ⚠️

**CyberTrace** is designed for **lawful investigations only**:
- ✅ Use for cyber investigations (with proper authority)
- ✅ Threat intelligence gathering
- ✅ Educational purposes
- ❌ Do NOT use for unauthorized access or hacking
- ❌ Do NOT harass or stalk individuals
- ❌ Respect privacy laws and regulations

All data is sourced from **public OSINT methods**. Ensure compliance with local laws before using.

---

## Author

Built for **Cyber Cell Investigations**  
**APCSIP-2026 | Amroha Police Cybersecurity**

---

## License

This project is provided as-is for authorized cyber investigations and educational use.

---

## Support

For issues, questions, or feature requests, open an issue on the GitHub repository.

**Stay safe. Investigate responsibly.**
