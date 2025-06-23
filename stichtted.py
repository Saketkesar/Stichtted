# STICHTTED v2.0 - Enhanced PCAP Flag & Artifact Extractor Tool

import argparse
import os
import re
import base64
import time
import gzip
import io
from scapy.all import rdpcap, TCP, Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

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
┌──────────────────────────────────────────────┐
│               STICHTTED v2.0                 │
│     PCAP Flag & Artifact Extractor Tool      │
│             Made by: S4k3t                   │
└──────────────────────────────────────────────┘
  For \U0001F525 CTF hunters, cyber pros, and analysts.
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

# Pattern matcher with context
def search_pattern(data, pattern):
    results = []
    for variant in recursive_decode(data):
        for match in re.finditer(pattern, variant):
            context = variant[match.start():match.end()+60]
            results.append((match.group(), "Recursive", context))
    return results

# Artifact extractor
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

# Try decompressing gzip

def try_decompress(data):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            return f.read().decode('utf-8', errors='ignore')
    except:
        return None

# TCP Stream reconstruction (naive)
def reassemble_tcp_payloads(packets):
    sessions = packets.sessions()
    data_streams = []
    for session in sessions:
        payload = ""
        for pkt in sessions[session]:
            if pkt.haslayer(Raw):
                payload += pkt[Raw].load.decode('utf-8', errors='ignore')
        if payload:
            data_streams.append(payload)
    return data_streams

# PCAP analyzer
def analyze(file_path, regex):
    results = []
    try:
        packets = rdpcap(file_path)
        data_streams = reassemble_tcp_payloads(packets)

        for stream in data_streams:
            stream_results = search_pattern(stream, regex) + extract_artifacts(stream)
            for match, typ, context in stream_results:
                results.append({
                    "match": match,
                    "type": typ,
                    "context": context,
                    "packet_index": "TCP_Stream",
                    "summary": "Reassembled TCP Stream",
                    "packet": stream[:400]  # show trimmed dump
                })

        for i, pkt in enumerate(packets):
            layers = []
            if pkt.haslayer(Raw):
                data = pkt[Raw].load
                try:
                    data = data.decode('utf-8', errors='ignore')
                except: continue

                if try_decompress(pkt[Raw].load):
                    data = try_decompress(pkt[Raw].load)

                matches = search_pattern(data, regex) + extract_artifacts(data)
                for match, typ, context in matches:
                    results.append({
                        "match": match,
                        "type": typ,
                        "context": context,
                        "packet_index": i,
                        "summary": pkt.summary(),
                        "packet": str(pkt)
                    })

            elif pkt.haslayer(DNS):
                if pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname.decode()
                    if re.search(regex, qname):
                        results.append({
                            "match": qname,
                            "type": "DNS Query",
                            "context": qname,
                            "packet_index": i,
                            "summary": pkt.summary(),
                            "packet": str(pkt)
                        })

    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    return results

# Show results
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

# Main

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
