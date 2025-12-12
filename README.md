# PHISHGUARD: URL Phishing Detection Tool (Python)

PhishGuard is a lightweight, rule-based phishing detection engine that analyzes URLs for suspicious patterns and generates a structured risk report.  
It is designed for learners, security beginners, and anyone who wants to understand how phishing detection logic works under the hood.

---

##  Features

- URL parsing (scheme, domain, subdomain, TLD, path, params)  
- Rule-based phishing detection  
- Fuzzy similarity matching for brand impersonation (RapidFuzz)  
- Detection of:
  - IP-based URLs  
  - @-trick redirects  
  - Suspicious keywords  
  - Hyphenated subdomains  
  - Look-alike domains (paypa1 → paypal)  
- Configurable scoring thresholds  
- Clean CLI interface  
- Bulk file scanning  
- JSON export  
- Summary report  
- Modular architecture

---

## 📁 Project Structure
phishguard/
│
├── core/
│ ├── parser.py
│ ├── rules.py
│ ├── scorer.py
│ ├── utils.py
│ └── init.py
│
├── data/
│ ├── whitelist.txt
│ └── thresholds.json
│
├── examples/
│ └── sample_urls.txt
│
├── tests/
│ ├── test_parser.py
│ └── test_rules.py
│
├── phishguard.py
└── requirements.txt
---

##  Installation

### 1. Clone the repository

```bash
git clone https://github.com/siddharthkm-06/phishguard
cd phishguard 
```

### 2. Create a virtual environment
```
python -m venv venv
```

### 3. Activate the environment

Windows:
```
venv\Scripts\activate
```

### 4. Install dependencies
```
pip install -r requirements.txt
```

---

## Usage 
### Scan a single URL:

```
python phishguard.py scan http://example.com
```

### Scan a file of URLs:
```
python phishguard.py scan examples/sample_urls.txt
```

### JSON output:
```
python phishguard.py --json scan http://example.com
```

## How Scoring Works

### PhishGuard scores URLs based on:

- Suspicious keywords

- Suspicious TLDs

- Subdomain tricking

- @ redirect tricks

- IP addresses

- Fuzzy similarity to known brands

- Query structure

- Look-alike domain patterns

### Severity levels:

Severity	             Meaning
HIGH	        Strong indicators of phishing
MEDIUM	        Multiple suspicious traits
LOW	            Minimal risk detected

Thresholds is in data/thresholds.json

## Example Output

============================================================
URL: http://secure-login.paypa1.com/reset
Risk Score: 45 (MEDIUM)
Detected Issues:
 1. Contains phishing-like keyword(s): login, secure-login, reset, secure
 2. High similarity to brand 'paypal' (score 90.9)
Summary:
  Several suspicious indicators detected. Exercise caution with this URL.
============================================================
