# STICHTTED v3.0 - Enhanced PCAP Flag & Artifact Extractor Tool with PyShark

import argparse
import os
import re
import base64
import time
import gzip
import io
from collections import defaultdict
from scapy.all import rdpcap, TCP, Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
import pyshark

# Color & Icons
RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
ICON_FILE = "\U0001F4C4"
ICON_FOLDER = "\U0001F4C1"
ICON_FOUND = "\u2705"
ICON_NOT_FOUND = "\u274C"

# Banner

def print_banner():
    banner = f"""{CYAN}
┌──────────────────────────────────────────────────────────────┐
│                      STICHTTED v3.0                          │
│       PCAP and PCAPNG Flag & Artifact Extractor Tool         │
│                  Made with ♥ by S4k3t                        │
└──────────────────────────────────────────────────────────────┘
🔗 GitHub: https://github.com/Saketkesar/Stichtted ⭐ Give a Star!
{RESET}"""
    print(banner)
    time.sleep(1)

# Spinner loading

def loading(task="Processing", seconds=2):
    spinner = ['|', '/', '-', '\\']
    print(task, end='', flush=True)
    for _ in range(seconds * 4):
        for c in spinner:
            print(f"\b{c}", end='', flush=True)
            time.sleep(0.1)
    print('\b ', end='')

# Recursive decoder

def recursive_decode(data, depth=2):
    outputs = [data]
    for _ in range(depth):
        new_outputs = []
        for d in outputs:
            try:
                b64 = base64.b64decode(d).decode('utf-8', errors='ignore')
                new_outputs.append(b64)
            except: pass
            try:
                hx = bytes.fromhex(d).decode('utf-8', errors='ignore')
                new_outputs.append(hx)
            except: pass
        outputs.extend(new_outputs)
    return list(set(outputs))

# Pattern matcher with context and source

def search_pattern(data, pattern, source_label):
    results = []
    for variant in recursive_decode(data):
        for match in re.finditer(pattern, variant):
            context = variant[match.start():match.end()+60]
            results.append((match.group(), "Recursive", context, source_label))
    return results

# Artifact extractor

def extract_artifacts(data, source_label):
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
            results.append((match.group(), label, context, source_label))
    return results

# Try decompressing gzip

def try_decompress(data):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            return f.read().decode('utf-8', errors='ignore')
    except:
        return None

# TCP Stream reconstruction

def reassemble_tcp_payloads(packets):
    sessions = packets.sessions()
    data_streams = []
    for session in sessions:
        payload = ""
        for pkt in sessions[session]:
            if pkt.haslayer(Raw):
                payload += pkt[Raw].load.decode('utf-8', errors='ignore')
        if payload:
            data_streams.append((session, payload))
    return data_streams

# Analyze using PyShark

def analyze_with_pyshark(file_path, regex):
    results = []
    try:
        cap = pyshark.FileCapture(file_path, decode_as={"tcp.port==80":"http"}, use_json=True, include_raw=True)
        for pkt in cap:
            try:
                if hasattr(pkt, 'http'):
                    fields = [getattr(pkt.http, attr) for attr in dir(pkt.http) if not attr.startswith('_')]
                    for field in fields:
                        if isinstance(field, str):
                            matches = search_pattern(field, regex, f"HTTP field in Packet #{pkt.number}")
                            matches += extract_artifacts(field, f"HTTP field in Packet #{pkt.number}")
                            for match, typ, context, src in matches:
                                results.append({
                                    "match": match,
                                    "type": f"HTTP:{typ}",
                                    "context": context,
                                    "source": src,
                                    "packet_index": pkt.number,
                                    "summary": f"{pkt.highest_layer} Packet",
                                    "packet": field[:300]
                                })
                if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                    dns_data = pkt.dns.qry_name
                    matches = search_pattern(dns_data, regex, f"DNS Query #{pkt.number}")
                    for match, typ, context, src in matches:
                        results.append({
                            "match": match,
                            "type": f"DNS:{typ}",
                            "context": context,
                            "source": src,
                            "packet_index": pkt.number,
                            "summary": f"DNS Query",
                            "packet": dns_data
                        })
            except Exception:
                continue
        cap.close()
    except Exception as e:
        print(f"{RED}PyShark Error: {e}{RESET}")
    return results

# Scapy analyzer

def analyze_with_scapy(file_path, regex):
    results = []
    try:
        packets = rdpcap(file_path)
        data_streams = reassemble_tcp_payloads(packets)

        for session, stream in data_streams:
            stream_results = search_pattern(stream, regex, f"TCP Session: {session}")
            stream_results += extract_artifacts(stream, f"TCP Session: {session}")
            for match, typ, context, src in stream_results:
                results.append({
                    "match": match,
                    "type": typ,
                    "context": context,
                    "source": src,
                    "packet_index": "TCP_Stream",
                    "summary": "Reassembled TCP Stream",
                    "packet": stream[:400]
                })
    except Exception as e:
        print(f"{RED}Scapy Error: {e}{RESET}")
    return results

# Result printer

def show(results):
    if results:
        match_counter = defaultdict(int)
        for r in results:
            match_counter[r['match']] += 1
            print(f"\n  {GREEN}{ICON_FOUND} Found: {r['match']}{RESET}")
            print(f"    ↪ Type     : {MAGENTA}{r['type']}{RESET}")
            print(f"    ↪ Source   : {CYAN}{r['source']}{RESET}")
            print(f"    ↪ Context  : {YELLOW}{r['context']}{RESET}")
            print(f"    ↪ Packet #{r['packet_index']}: {r['summary']}")
            print(f"    ↪ Dump     :\n{CYAN}{r['packet']}{RESET}\n")
        print(f"\n{GREEN}✅ Total Matches Found: {len(results)}{RESET}")
    else:
        print(f"{RED}{ICON_NOT_FOUND} No matches found.{RESET}")

# Main

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="STICHTTED: Flag & Artifact Extractor by S4k3t")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='PCAP/PCAPNG file to scan')
    group.add_argument('-d', '--directory', help='Directory of PCAPs')
    parser.add_argument('-l', '--lookup', required=True, help='Regex pattern to look for')
    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            print(f"{RED}❌ Invalid file: {args.file}{RESET}")
            return
        print(f"{ICON_FILE} Analyzing: {CYAN}{args.file}{RESET}")
        loading("   Parsing ")
        results = analyze_with_scapy(args.file, args.lookup)
        results += analyze_with_pyshark(args.file, args.lookup)
        show(results)

    elif args.directory:
        if not os.path.isdir(args.directory):
            print(f"{RED}❌ Invalid directory: {args.directory}{RESET}")
            return
        print(f"{ICON_FOLDER} Scanning: {YELLOW}{args.directory}{RESET}")
        for f in os.listdir(args.directory):
            if f.endswith(".pcap") or f.endswith(".pcapng"):
                path = os.path.join(args.directory, f)
                print(f"\n{ICON_FILE} File: {CYAN}{f}{RESET}")
                loading("   Parsing ")
                results = analyze_with_scapy(path, args.lookup)
                results += analyze_with_pyshark(path, args.lookup)
                show(results)

if __name__ == "__main__":
    main()
