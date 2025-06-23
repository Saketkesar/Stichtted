# stichtted v2.0

**stichtted** is a fast, hacker-grade PCAP analyzer designed for CTF players, bug bounty hunters, and cybersecurity professionals. Extract CTF flags, secrets, JWTs, URLs, IPs, and encoded data from packet captures with smart context and full raw packet dumps.

![stichtted demo](https://iili.io/FIFKR4I.png)

---

## 🔍 Features

- Regex-based pattern matching (`HTB{}`, `CTF{}`, `SKT{}` etc.)
- Auto artifact extraction:
  - Flags
  - URLs (http/https)
  - JWT Tokens
  - IP Addresses
  - Emails
- Detects Base64 and Hex encoded payloads
- Full packet content and context shown
- Folder and file-level `.pcap` analysis
- Clean CLI with banner and terminal feedback

---

## ⚙ Requirements

- Python 3.8+
- Scapy

Install with:

```bash
pip install -r requirements.txt
```

**requirements.txt**:
```
scapy
```

---

## 🚀 Installation

```bash
git clone https://github.com/Saketkesar/Stichtted.git
cd Stichtted

pip install -r requirements.txt
```

---

## 🔧 Usage

```bash
# Analyze single PCAP for CTF flags
python3 stichtted.py -f dump.pcap -l "HTB{.*?}"

# Search for a specific flag pattern
python3 stichtted.py -f flag_encoded.pcap -l "SKT{.*?}"

# Extract secrets from all PCAPs in a directory
python3 stichtted.py -d ./pcaps -l "CTF{.*?}"

# Search for URLs
python3 stichtted.py -f netlog.pcap -l "https://[a-zA-Z0-9./?=_-]+"
```

---

## 📦 Output Example

- Shows the match
- Type of match (Plain, Base64, Hex, Auto)
- Context (next 50-60 characters)
- Packet number
- Full raw packet summary

---

## 🛠 Built For

- CTFs (Capture The Flag)
- Cybersecurity research
- Network forensics
- Red team packet review
- Malware traffic analysis


## 👨‍💻 Author

**Made by [S4k3t](https://github.com/Saketkesar/)**  
