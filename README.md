
# stichtted v3.0

**stichtted** is a high-performance PCAP artifact extraction tool crafted for CTF players, red teamers, bug bounty hunters, and cyber professionals. It detects and extracts **flags**, **JWTs**, **URLs**, **IPs**, **emails**, and **encoded payloads** (Base64, hex) from `.pcap` **and now also `.pcapng`** files — thanks to PyShark integration and stream reassembly logic.

![stichtted demo](https://iili.io/FIX0p2I.png)

---

## 🔍 Features

- 🎯 Regex-powered match detection (`HTB{}`, `CTF{}`, `SKT{}` etc.)
- 🧠 Auto artifact detection:
  - URLs, JWTs, IPs, and Emails
- 🔁 Recursive Base64 and hex decoding
- 🧬 HTTP header/body analysis via PyShark
- 📡 DNS tunneling detection (e.g., Base64 in subdomains)
- 📥 Reassembled TCP stream analysis (via Scapy)
- 📂 Scan folders with multiple `.pcap` **and `.pcapng`** files
- 📍 Full context, packet number, source layer & decoded dump
- 

---

## ⚙ Requirements

- Python 3.8+
- `scapy`
- `pyshark` *(requires `tshark` installed)*

Install dependencies with:

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
scapy
pyshark
```

---

## 🚀 Installation

```bash
git clone https://github.com/Saketkesar/Stichtted.git
cd Stichtted

pip install -r requirements.txt
```

Make sure `tshark` is installed:

```bash
sudo apt install tshark
```

---

## 🔧 Usage

```bash
# Scan single pcap file for CTF flags
python3 stichtted.py -f capture.pcap -l "HTB{.*?}"

# Search for Base64-encoded flags like SKT{...}
python3 stichtted.py -f encoded.pcap -l "SKT{.*?}"

# Extract from all pcaps and pcapngs in a directory
python3 stichtted.py -d ./pcaps -l "CTF{.*?}"

# Search for URLs
python3 stichtted.py -f traffic.pcap -l "https://[a-zA-Z0-9./?=_-]+"
```

---

## 📦 Output Example

```bash
✅ Found: SKT{hidden_encoded_flag}
  ↪ Type     : Recursive
  ↪ Source   : HTTP field in Packet #42
  ↪ Context  : SKT{hidden_encoded_flag}...
  ↪ Packet #42: HTTP Packet
  ↪ Dump     : [Base64 dump or decoded stream]

✅ Found: SKT{another_flag}
  ↪ Source   : TCP Session: 192.168.0.1:4567 → 10.0.0.1:80

📌 Total Matches Found: 2
```

---

## 🛠 Ideal For

- CTF competitions (HackTheBox, PicoCTF, etc.)
- Malware traffic inspection
- Red team network dumps
- Threat intelligence
- Recon/Forensics
- DNS covert channel analysis

---

## 📚 Examples of What It Extracts

- `CTF{flag}`
- `https://malicious.site/login`
- `eyJ0eXAiOiJKV1Qi...` (JWT)
- `192.168.1.1`
- `s4k3t@exploit.com`

---

## 👨‍💻 Author

**Made with ❤️ by [S4k3t](https://github.com/Saketkesar/)**  
👉 GitHub Repo: [Stichtted](https://github.com/Saketkesar/Stichtted) ⭐ Give it a Star!

---