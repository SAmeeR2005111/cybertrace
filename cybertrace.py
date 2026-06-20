#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║           CyberTrace OSINT Suite v1.0                        ║
║      Built for Cyber Cell Investigations                      ║
║      APCSIP-2026 | Amroha Police Cybersecurity               ║
╚═══════════════════════════════════════════════════════════════╝
"""

import sys
import os
import json
import time
import socket
import struct
import re
import ipaddress
from datetime import datetime

# ── Optional dependency imports (graceful fallback) ─────────────
try:
    # dynamic import to avoid static analysis false-positives in some editors
    import importlib
    requests = importlib.import_module('requests')
    REQUESTS_OK = True
except Exception:
    # requests unavailable at runtime
    requests = None
    REQUESTS_OK = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_OK = True
except ImportError:
    PIL_OK = False

try:
    import whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ── ANSI Colors ─────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def color(text, *codes):
    return "".join(codes) + str(text) + C.RESET

def banner():
    print(color("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗██╗   ██╗██████╗ ███████╗██████╗                   ║
║   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗                  ║
║   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝                  ║
║   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗                  ║
║   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║                  ║
║    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝  TRACE           ║
║                                                               ║
║         OSINT Suite v1.0 | Cyber Cell Edition                 ║
║         APCSIP-2026 | Amroha Police Cybersecurity             ║
╚═══════════════════════════════════════════════════════════════╝
""", C.CYAN, C.BOLD))

def section(title):
    print("\n" + color("─" * 60, C.DIM))
    print(color(f"  ▶  {title}", C.YELLOW, C.BOLD))
    print(color("─" * 60, C.DIM))

def ok(msg):    print(color(f"  [✓] {msg}", C.GREEN))
def warn(msg):  print(color(f"  [!] {msg}", C.YELLOW))
def err(msg):   print(color(f"  [✗] {msg}", C.RED))
def info(msg):  print(color(f"  [→] {msg}", C.CYAN))
def found(k,v): print(color(f"  {k:<22}", C.WHITE) + color(str(v), C.MAGENTA))

def save_report(data: dict, filename: str):
    """Save investigation report to JSON file."""
    path = os.path.join(os.getcwd(), filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    ok(f"Report saved → {path}")

# ════════════════════════════════════════════════════════════════
#  MODULE 1 — USERNAME HUNT
# ════════════════════════════════════════════════════════════════

PLATFORMS = {
    "Instagram":    "https://www.instagram.com/{}",
    "Twitter/X":    "https://twitter.com/{}",
    "GitHub":       "https://github.com/{}",
    "Reddit":       "https://www.reddit.com/user/{}",
    "TikTok":       "https://www.tiktok.com/@{}",
    "Pinterest":    "https://www.pinterest.com/{}",
    "LinkedIn":     "https://www.linkedin.com/in/{}",
    "YouTube":      "https://www.youtube.com/@{}",
    "Twitch":       "https://www.twitch.tv/{}",
    "Telegram":     "https://t.me/{}",
    "Medium":       "https://medium.com/@{}",
    "DevTo":        "https://dev.to/{}",
    "Keybase":      "https://keybase.io/{}",
    "HackerNews":   "https://news.ycombinator.com/user?id={}",
    "ProductHunt":  "https://www.producthunt.com/@{}",
    "Pastebin":     "https://pastebin.com/u/{}",
    "Gitlab":       "https://gitlab.com/{}",
    "Bitbucket":    "https://bitbucket.org/{}",
    "StackOverflow":"https://stackoverflow.com/users/{}",
    "Quora":        "https://www.quora.com/profile/{}",
    "Snapchat":     "https://www.snapchat.com/add/{}",
    "VK":           "https://vk.com/{}",
    "Tumblr":       "https://{}.tumblr.com",
    "WordPress":    "https://{}.wordpress.com",
    "Blogger":      "https://{}.blogspot.com",
}

def username_hunt(username: str):
    section(f"USERNAME HUNT  →  {username}")
    if not REQUESTS_OK:
        err("'requests' library not installed. Run: pip install requests")
        return {}

    results = {"username": username, "found": [], "not_found": [], "timestamp": str(datetime.now())}
    total = len(PLATFORMS)
    found_count = 0

    info(f"Scanning {total} platforms...\n")

    for platform, url_template in PLATFORMS.items():
        url = url_template.format(username)
        try:
            resp = requests.get(url, timeout=6, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0"})
            # Heuristic: 200 and page isn't a generic "user not found" page
            if resp.status_code == 200 and len(resp.text) > 500:
                ok(f"{platform:<18} {color('FOUND', C.GREEN, C.BOLD)}  →  {url}")
                results["found"].append({"platform": platform, "url": url})
                found_count += 1
            else:
                print(color(f"  [–] {platform:<18} not found", C.DIM))
                results["not_found"].append(platform)
        except requests.exceptions.Timeout:
            warn(f"{platform:<18} timeout")
        except Exception:
            print(color(f"  [–] {platform:<18} error", C.DIM))
        time.sleep(0.15)  # polite delay

    print()
    info(f"Found on {found_count}/{total} platforms")
    return results


# ════════════════════════════════════════════════════════════════
#  MODULE 2 — EMAIL / PHONE INTELLIGENCE
# ════════════════════════════════════════════════════════════════

def validate_email(email: str) -> dict:
    result = {}
    pattern = r'^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$'
    result["valid_format"] = bool(re.match(pattern, email))
    if "@" in email:
        parts = email.split("@")
        result["username"] = parts[0]
        result["domain"]   = parts[1]
        # Check for known disposable/temp email providers
        disposable = ["mailinator","guerrillamail","tempmail","throwam","yopmail",
                      "sharklasers","guerrillamailblock","grr.la","spam4.me"]
        result["possibly_disposable"] = any(d in parts[1].lower() for d in disposable)
        # Known provider hints
        providers = {
            "gmail.com": "Google", "yahoo.com": "Yahoo", "outlook.com": "Microsoft",
            "hotmail.com": "Microsoft", "protonmail.com": "ProtonMail",
            "rediffmail.com": "Rediff (India)", "yandex.com": "Yandex",
        }
        result["provider"] = providers.get(parts[1].lower(), "Unknown")
        # Domain MX check
        if DNS_OK:
            try:
                mx = dns.resolver.resolve(parts[1], 'MX')
                result["mx_records"] = [str(r.exchange) for r in mx]
                result["domain_has_mx"] = True
            except Exception:
                result["domain_has_mx"] = False
    return result

def validate_phone(phone: str) -> dict:
    result = {}
    digits = re.sub(r'\D', '', phone)
    result["cleaned"] = digits
    result["length"]  = len(digits)

    # India-specific analysis
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    if len(digits) == 10:
        result["country"] = "India (likely)"
        result["valid_length"] = True
        prefix = int(digits[:4])
        # Telecom circle heuristics (based on number series)
        operator_map = {
            "6": "Jio / Airtel / Vi",
            "7": "Jio / Airtel / BSNL",
            "8": "Airtel / Vi / BSNL",
            "9": "Airtel / Jio / Vi",
        }
        result["possible_operator"] = operator_map.get(digits[0], "Unknown")
        result["number_type"] = "Mobile"
        if digits.startswith(("1800","1860","140")):
            result["number_type"] = "Toll-free / Service number"
    else:
        result["valid_length"] = False
        result["note"] = "Not a standard 10-digit Indian mobile number"

    # Pattern flags
    result["all_same_digits"]    = len(set(digits)) == 1
    result["sequential_pattern"] = digits in "0123456789" or digits in "9876543210"

    return result

def email_phone_intel(target: str):
    section(f"EMAIL / PHONE INTELLIGENCE  →  {target}")
    report = {"target": target, "timestamp": str(datetime.now())}

    if "@" in target:
        info("Detected: Email address")
        result = validate_email(target)
        report["type"] = "email"
        report["analysis"] = result

        found("Format Valid",        result.get("valid_format"))
        found("Username",            result.get("username", "—"))
        found("Domain",              result.get("domain", "—"))
        found("Provider",            result.get("provider", "—"))
        found("Possibly Disposable", result.get("possibly_disposable"))
        found("Domain Has MX",       result.get("domain_has_mx", "DNS check unavailable"))
        if result.get("mx_records"):
            found("MX Records",      ", ".join(result["mx_records"][:2]))

        # HIBP breach check hint
        print()
        warn("For breach check, visit: https://haveibeenpwned.com/unifiedsearch/" + target)
        info("HaveIBeenPwned API requires a key — integrate with: pip install hibp")

    else:
        info("Detected: Phone number")
        result = validate_phone(target)
        report["type"] = "phone"
        report["analysis"] = result

        found("Cleaned Number",      result.get("cleaned"))
        found("Length",              result.get("length"))
        found("Valid Length",        result.get("valid_length"))
        found("Country",             result.get("country", "Unknown"))
        found("Possible Operator",   result.get("possible_operator", "—"))
        found("Number Type",         result.get("number_type", "—"))
        found("Suspicious Pattern",  result.get("all_same_digits") or result.get("sequential_pattern"))

        print()
        info("For carrier lookup: https://www.truecaller.com (manual)")
        info("For legal CDR request: Submit via CyberCrime portal")

    return report


# ════════════════════════════════════════════════════════════════
#  MODULE 3 — IMAGE OSINT (EXIF)
# ════════════════════════════════════════════════════════════════

def dms_to_decimal(dms, ref):
    """Convert GPS DMS tuple to decimal degrees."""
    try:
        d = float(dms[0])
        m = float(dms[1])
        s = float(dms[2])
        decimal = d + m/60 + s/3600
        if ref in ['S', 'W']:
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None

def image_osint(path: str):
    section(f"IMAGE OSINT  →  {os.path.basename(path)}")

    if not os.path.exists(path):
        err(f"File not found: {path}")
        return {}

    report = {"file": path, "timestamp": str(datetime.now())}

    # ── Basic file info ────────────────────────────────────────
    stat = os.stat(path)
    report["file_size_bytes"] = stat.st_size
    report["modified_time"]   = str(datetime.fromtimestamp(stat.st_mtime))
    found("File Size",    f"{stat.st_size:,} bytes ({stat.st_size/1024:.1f} KB)")
    found("Last Modified", datetime.fromtimestamp(stat.st_mtime))

    ext = os.path.splitext(path)[1].lower()
    found("Extension", ext)

    if not PIL_OK:
        err("Pillow not installed. Run: pip install Pillow")
        return report

    try:
        img = Image.open(path)
        found("Image Size",   f"{img.width} × {img.height} px")
        found("Color Mode",   img.mode)
        found("Format",       img.format)
        report["width"]  = img.width
        report["height"] = img.height
        report["format"] = img.format
        report["mode"]   = img.mode

        # ── EXIF extraction ────────────────────────────────────
        exif_data = img._getexif() if hasattr(img, '_getexif') else None
        if not exif_data:
            # Try newer method
            try:
                from PIL.ExifTags import TAGS
                exif_data = {TAGS.get(k, k): v for k, v in img.getexif().items()}
            except Exception:
                exif_data = None

        if exif_data:
            ok("EXIF metadata found!")
            report["exif"] = {}

            gps_info = None
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, str(tag_id)) if isinstance(tag_id, int) else str(tag_id)
                if tag_name == "GPSInfo":
                    gps_info = value
                    continue
                # Show important fields
                important = ["Make","Model","Software","DateTime","DateTimeOriginal",
                             "DateTimeDigitized","Orientation","Flash","FocalLength",
                             "ExposureTime","ISOSpeedRatings","Artist","Copyright",
                             "ImageDescription","XResolution","YResolution"]
                str_val = str(value)[:80]
                if tag_name in important:
                    found(tag_name, str_val)
                    report["exif"][tag_name] = str_val

            # ── GPS coordinates ────────────────────────────────
            if gps_info:
                ok("GPS DATA FOUND — Location embedded in image!")
                report["gps"] = {}
                gps_decoded = {}
                for key, val in gps_info.items():
                    gps_tag = GPSTAGS.get(key, key)
                    gps_decoded[gps_tag] = val

                lat = lon = None
                if "GPSLatitude" in gps_decoded and "GPSLatitudeRef" in gps_decoded:
                    lat = dms_to_decimal(gps_decoded["GPSLatitude"],
                                         gps_decoded["GPSLatitudeRef"])
                if "GPSLongitude" in gps_decoded and "GPSLongitudeRef" in gps_decoded:
                    lon = dms_to_decimal(gps_decoded["GPSLongitude"],
                                         gps_decoded["GPSLongitudeRef"])

                if lat and lon:
                    found("Latitude",  lat)
                    found("Longitude", lon)
                    maps_url = f"https://maps.google.com/?q={lat},{lon}"
                    found("Google Maps", maps_url)
                    report["gps"] = {"latitude": lat, "longitude": lon, "maps_url": maps_url}
                    warn("This image contains precise GPS location data!")
                else:
                    warn("GPS tags present but coordinates could not be decoded")
            else:
                info("No GPS data found in EXIF")
        else:
            warn("No EXIF metadata found (possibly stripped)")
            report["exif"] = None

        # ── Reverse image search links ─────────────────────────
        print()
        info("Reverse Image Search (manual):")
        print(color("  → Google:   https://images.google.com (upload image)", C.DIM))
        print(color("  → TinEye:   https://tineye.com", C.DIM))
        print(color("  → Yandex:   https://yandex.com/images", C.DIM))

    except Exception as e:
        err(f"Could not process image: {e}")

    return report


# ════════════════════════════════════════════════════════════════
#  MODULE 4 — DOMAIN / IP RECON
# ════════════════════════════════════════════════════════════════

def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def ip_recon(ip: str) -> dict:
    result = {}
    if not REQUESTS_OK:
        warn("requests not installed — skipping IP geolocation")
        return result
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            result = data
            fields = ["ip","city","region","country_name","org","isp",
                      "timezone","latitude","longitude","asn"]
            for f in fields:
                if data.get(f):
                    found(f.replace("_"," ").title(), data[f])
    except Exception as e:
        warn(f"IP geolocation failed: {e}")
    return result

def domain_recon(target: str):
    section(f"DOMAIN / IP RECON  →  {target}")
    report = {"target": target, "timestamp": str(datetime.now())}

    # Strip protocol if present
    domain = re.sub(r'^https?://', '', target).split('/')[0]
    report["domain"] = domain

    # ── IP Resolution ──────────────────────────────────────────
    try:
        ip = socket.gethostbyname(domain)
        found("Resolved IP",  ip)
        report["ip"] = ip
        # Check if private
        try:
            is_private = ipaddress.ip_address(ip).is_private
            found("IP Type",  "Private/Internal" if is_private else "Public")
        except Exception:
            pass
    except Exception:
        err("Could not resolve domain to IP")
        ip = None

    # ── IP Geolocation ─────────────────────────────────────────
    target_ip = target if is_ip(target) else ip
    if target_ip:
        info("IP Geolocation:")
        geo = ip_recon(target_ip)
        report["geolocation"] = geo

    # ── WHOIS ──────────────────────────────────────────────────
    if WHOIS_OK:
        try:
            info("WHOIS lookup...")
            w = whois.whois(domain)
            whois_data = {}
            for field in ["registrar","creation_date","expiration_date",
                           "updated_date","name_servers","status","emails",
                           "dnssec","org","country"]:
                val = getattr(w, field, None)
                if val:
                    display_val = val[0] if isinstance(val, list) else val
                    found(field.replace("_"," ").title(), str(display_val)[:60])
                    whois_data[field] = str(display_val)
            report["whois"] = whois_data
        except Exception as e:
            warn(f"WHOIS failed: {e}")
    else:
        warn("python-whois not installed. Run: pip install python-whois")

    # ── DNS Records ────────────────────────────────────────────
    if DNS_OK:
        info("DNS Records:")
        dns_data = {}
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records = [str(r) for r in answers]
                found(f"DNS {rtype}", ", ".join(records[:3]))
                dns_data[rtype] = records
            except Exception:
                pass
        report["dns"] = dns_data
    else:
        warn("dnspython not installed. Run: pip install dnspython")

    # ── Threat Intel links (manual) ────────────────────────────
    print()
    info("Threat Intelligence (manual check):")
    print(color(f"  → VirusTotal:   https://www.virustotal.com/gui/domain/{domain}", C.DIM))
    print(color(f"  → AbuseIPDB:    https://www.abuseipdb.com/check/{target_ip or domain}", C.DIM))
    print(color(f"  → Shodan:       https://www.shodan.io/search?query={target_ip or domain}", C.DIM))
    print(color(f"  → URLScan:      https://urlscan.io/search/#{domain}", C.DIM))

    # ── HTTP Headers ───────────────────────────────────────────
    if REQUESTS_OK:
        try:
            info("HTTP Headers:")
            r = requests.get(f"https://{domain}", timeout=6,
                             headers={"User-Agent": "Mozilla/5.0"})
            headers_of_interest = ["Server","X-Powered-By","X-Frame-Options",
                                   "Strict-Transport-Security","Content-Security-Policy",
                                   "X-Content-Type-Options","Set-Cookie", "Content-Type","Origin","Allow-Control-Allow-Origin"]
            headers_data = {}
            for h in headers_of_interest:
                val = r.headers.get(h)
                if val:
                    found(h, str(val)[:60])
                    headers_data[h] = val
            report["http_headers"] = headers_data
            report["http_status"] = r.status_code
            found("HTTP Status", r.status_code)
        except Exception:
            pass

    return report


# ════════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════════

def main_menu():
    banner()
    print(color("  Select Investigation Module:\n", C.WHITE))
    print(color("  [1]", C.CYAN, C.BOLD) + "  Username Hunt       — find accounts across 25+ platforms")
    print(color("  [2]", C.CYAN, C.BOLD) + "  Email/Phone Intel   — validate, analyze, breach hints")
    print(color("  [3]", C.CYAN, C.BOLD) + "  Image OSINT         — EXIF, GPS, metadata extraction")
    print(color("  [4]", C.CYAN, C.BOLD) + "  Domain/IP Recon     — WHOIS, DNS, geo, threat intel")
    print(color("  [5]", C.CYAN, C.BOLD) + "  Full Investigation  — run all modules on a target")
    print(color("  [0]", C.RED)          + "  Exit\n")

def run():
    if len(sys.argv) > 1:
        # Direct CLI usage: python cybertrace.py <module> <target>
        module = sys.argv[1]
        target = sys.argv[2] if len(sys.argv) > 2 else None
        if module == "username" and target:
            r = username_hunt(target)
            save_report(r, f"report_username_{target}.json")
        elif module == "email" and target:
            r = email_phone_intel(target)
            save_report(r, f"report_email_{target.replace('@','_at_')}.json")
        elif module == "image" and target:
            r = image_osint(target)
            save_report(r, f"report_image_{os.path.basename(target)}.json")
        elif module == "domain" and target:
            r = domain_recon(target)
            save_report(r, f"report_domain_{target}.json")
        else:
            print("Usage: python cybertrace.py [username|email|image|domain] <target>")
        return

    # Interactive menu
    while True:
        main_menu()
        choice = input(color("  Enter choice: ", C.YELLOW)).strip()

        if choice == "0":
            print(color("\n  Exiting CyberTrace. Stay safe.\n", C.DIM))
            break

        elif choice == "1":
            target = input(color("  Enter username: ", C.CYAN)).strip()
            if target:
                r = username_hunt(target)
                save = input(color("\n  Save report? (y/n): ", C.YELLOW)).strip().lower()
                if save == "y":
                    save_report(r, f"report_username_{target}.json")

        elif choice == "2":
            target = input(color("  Enter email or phone: ", C.CYAN)).strip()
            if target:
                r = email_phone_intel(target)
                save = input(color("\n  Save report? (y/n): ", C.YELLOW)).strip().lower()
                if save == "y":
                    save_report(r, f"report_intel_{target.replace('@','_at_')}.json")

        elif choice == "3":
            target = input(color("  Enter image path: ", C.CYAN)).strip()
            if target:
                r = image_osint(target)
                save = input(color("\n  Save report? (y/n): ", C.YELLOW)).strip().lower()
                if save == "y":
                    save_report(r, f"report_image_{os.path.basename(target)}.json")

        elif choice == "4":
            target = input(color("  Enter domain or IP: ", C.CYAN)).strip()
            if target:
                r = domain_recon(target)
                save = input(color("\n  Save report? (y/n): ", C.YELLOW)).strip().lower()
                if save == "y":
                    save_report(r, f"report_domain_{target}.json")

        elif choice == "5":
            print(color("\n  FULL INVESTIGATION MODE", C.MAGENTA, C.BOLD))
            username = input(color("  Username (or Enter to skip): ", C.CYAN)).strip()
            email    = input(color("  Email/Phone (or Enter to skip): ", C.CYAN)).strip()
            image    = input(color("  Image path (or Enter to skip): ", C.CYAN)).strip()
            domain   = input(color("  Domain/IP (or Enter to skip): ", C.CYAN)).strip()

            full_report = {"investigation": "full", "timestamp": str(datetime.now())}

            if username: full_report["username"]    = username_hunt(username)
            if email:    full_report["email_phone"] = email_phone_intel(email)
            if image:    full_report["image"]       = image_osint(image)
            if domain:   full_report["domain"]      = domain_recon(domain)

            save_report(full_report, f"report_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        else:
            err("Invalid choice. Please try again.")

        input(color("\n  Press Enter to continue...", C.DIM))

if __name__ == "__main__":
    run()
