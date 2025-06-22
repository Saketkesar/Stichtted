import argparse
import os
import re
import base64
import time
from scapy.all import rdpcap

# Color & Icons
RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
ICON_FILE = "📄"
ICON_FOLDER = "📁"
ICON_FOUND = "✅"
ICON_NOT_FOUND = "❌"

# Banner
def print_banner():
    banner = f"""{CYAN}
┌──────────────────────────────────────────────┐
│               STICHTTED v1.0                 │
│     PCAP Flag & Artifact Extractor Tool      │
│             Made by: S4k3t                   │
└──────────────────────────────────────────────┘
  For 🔥 CTF hunters, cyber pros, and analysts.

  🔍 Can Analyze:
    ✅ CTF flags     (HTB{{}}, SKT{{}}, CTF{{}}...)
    ✅ Encoded data  (Base64, Hex-encoded)
    ✅ URLs          (http://, https://...)
    ✅ JWT Tokens    (eyJ...eyJ...eyJ)
    ✅ IP Addresses  (192.168.x.x, etc.)
    ✅ Raw packet context (full packet dump)

  ⚙ Usage:
    python3 stichtted_ctf.py -f file.pcap -l "HTB{{.*?}}"
    python3 stichtted_ctf.py -f file.pcap -l "SKT{{.*?}}"
    python3 stichtted_ctf.py -d ./pcaps -l "CTF{{.*?}}"
    python3 stichtted_ctf.py -f file.pcap -l "https://[a-zA-Z0-9./?=_-]+"

  💡 Tip: Use -l "<regex>" to extract custom flags, secrets, or indicators.
{RESET}"""
    print(banner)
    time.sleep(1)

# Spinner loading
spinner = ['|', '/', '-', '\\']
def loading(task="Processing", seconds=2):
    print(task, end='', flush=True)
    for _ in range(seconds * 4):
        for c in spinner:
            print(f"\b{c}", end='', flush=True)
            time.sleep(0.1)
    print('\b ', end='')

# Pattern matcher with context
def search_pattern(data, pattern):
    results = []
    for match in re.finditer(pattern, data):
        context = data[match.start():match.end()+60]
        results.append((match.group(), "Plain", context))
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
        for match in re.finditer(pattern, decoded):
            context = decoded[match.start():match.end()+60]
            results.append((match.group(), "Base64", context))
    except: pass
    try:
        decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
        for match in re.finditer(pattern, decoded):
            context = decoded[match.start():match.end()+60]
            results.append((match.group(), "Hex", context))
    except: pass
    return results

# Auto pattern extraction
def extract_artifacts(data):
    results = []
    patterns = {
        "URL": r"https?://[^\s\"'<>]+",
        "IP": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    }
    for label, regex in patterns.items():
        for match in re.finditer(regex, data):
            context = data[match.start():match.end()+60]
            results.append((match.group(), label, context))
    return results

# PCAP analyzer
def analyze(file_path, regex):
    results = []
    try:
        packets = rdpcap(file_path)
        for i, pkt in enumerate(packets):
            if pkt.haslayer('Raw'):
                payload = bytes(pkt['Raw'].load)
                data = payload.decode('utf-8', errors='ignore')

                # Manual search
                matches = search_pattern(data, regex)
                # Auto artifact extraction
                artifacts = extract_artifacts(data)

                for match, typ, context in matches + artifacts:
                    results.append({
                        "match": match,
                        "type": typ,
                        "context": context,
                        "packet_index": i,
                        "summary": pkt.summary(),
                        "packet": str(pkt)
                    })
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    return results

# Result printer
def show(results):
    if results:
        for r in results:
            print(f"\n  {GREEN}{ICON_FOUND} Found: {r['match']}{RESET}")
            print(f"    ↪ Type     : {MAGENTA}{r['type']}{RESET}")
            print(f"    ↪ Context  : {YELLOW}{r['context']}{RESET}")
            print(f"    ↪ Packet #{r['packet_index']}: {r['summary']}")
            print(f"    ↪ Dump     :\n{CYAN}{r['packet']}{RESET}\n")
    else:
        print(f"{RED}{ICON_NOT_FOUND} No matches found.{RESET}")

# Main driver
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="CTF-grade PCAP search tool by S4k3t")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='PCAP file to scan')
    group.add_argument('-d', '--directory', help='Directory of PCAPs')
    parser.add_argument('-l', '--lookup', required=True, help='Regex pattern to look for')
    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            print(f"{RED}❌ Invalid file: {args.file}{RESET}")
            return
        print(f"{ICON_FILE} Analyzing: {CYAN}{args.file}{RESET}")
        loading("   Parsing ")
        results = analyze(args.file, args.lookup)
        show(results)

    elif args.directory:
        if not os.path.isdir(args.directory):
            print(f"{RED}❌ Invalid directory: {args.directory}{RESET}")
            return
        print(f"{ICON_FOLDER} Scanning: {YELLOW}{args.directory}{RESET}")
        for f in os.listdir(args.directory):
            if f.endswith(".pcap"):
                path = os.path.join(args.directory, f)
                print(f"\n{ICON_FILE} File: {CYAN}{f}{RESET}")
                loading("   Parsing ")
                results = analyze(path, args.lookup)
                show(results)

if __name__ == "__main__":
    main()
