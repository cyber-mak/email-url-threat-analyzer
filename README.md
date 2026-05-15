# 🔍 ThreatScan — Email & URL Threat Analyzer

A cybersecurity web tool that analyzes URLs and emails for phishing, malware, and social engineering threats using real-world threat intelligence APIs.

![ThreatScan Preview](screenshots/preview.png)

---

## 🚀 Live Demo

> Deploy to [Render.com](https://render.com) or [Railway.app](https://railway.app) for free.

---

## 🛡️ Features

- **URL Threat Analysis** — Scans any URL against 70+ antivirus engines via the VirusTotal API
- **Email Phishing Detection** — Parses email headers, checks SPF/DKIM auth, detects sender spoofing
- **URL Extraction** — Automatically pulls URLs from email bodies and scans each one
- **Urgency Keyword Detection** — Flags manipulation language common in phishing emails
- **Risk Scoring** — Generates a 0–100 threat score with color-coded verdict
- **Scan History** — Tracks past scans in the browser for quick reference
- **Demo Mode** — Works client-side even without a backend (for portfolio showcasing)

---

## 🏗️ Architecture

```
┌─────────────────────┐        HTTP POST         ┌──────────────────────────┐
│                     │  ───────────────────────► │                          │
│   Frontend          │  { url } or { email }     │   Flask Backend          │
│   HTML/CSS/JS       │                           │   Python 3.11            │
│                     │ ◄───────────────────────  │                          │
└─────────────────────┘    JSON threat report     └──────────┬───────────────┘
                                                             │
                                          ┌──────────────────┴──────────────────┐
                                          │                                     │
                                 ┌────────▼────────┐                ┌──────────▼────────┐
                                 │  url_checker.py  │                │ email_checker.py   │
                                 │                  │                │                    │
                                 │ • Base64 encode  │                │ • Parse headers    │
                                 │ • VT API submit  │                │ • Domain match     │
                                 │ • Parse 70+ eng  │                │ • SPF/DKIM check   │
                                 │ • Threat score   │                │ • Regex URL pull   │
                                 └────────┬────────┘                │ • Keyword detect   │
                                          │                          └──────────┬────────┘
                                          ▼                                     │
                               ┌──────────────────┐                            │
                               │  VirusTotal API  │◄───────────────────────────┘
                               │  virustotal.com  │   (each extracted URL scanned)
                               └──────────────────┘
```

---

## 🔬 How It Works

### URL Analysis
1. User pastes a URL into the frontend
2. Frontend sends a `POST /api/analyze-url` request to the Flask backend
3. Backend encodes the URL as **base64** (required by VirusTotal's API format)
4. Submits the URL to VirusTotal, which queues it for scanning across 70+ security engines
5. Fetches the analysis report — each engine votes: `malicious`, `suspicious`, `harmless`, or `undetected`
6. Calculates a **threat score**: `(malicious × 1.0 + suspicious × 0.5) / total_engines × 100`
7. Returns verdict (`SAFE` / `SUSPICIOUS` / `DANGEROUS`), score, domain age, and category

### Email Analysis
1. User pastes raw email text (including headers) into the frontend
2. Backend uses Python's built-in `email` library to parse the structured headers
3. **Sender spoofing check**: extracts the `From` domain and `Reply-To` domain — a mismatch is a major phishing indicator
4. **SPF/DKIM check**: reads `Received-SPF` and `Authentication-Results` headers added by mail servers to verify the sender's identity
5. **URL extraction**: uses **regex** (`https?://[^\s]+`) to find all links in the email body
6. Each extracted URL is run through the same VirusTotal check as the URL analyzer
7. **Keyword detection**: scans for urgency language like `"verify"`, `"urgent"`, `"account suspended"` — common social engineering tactics
8. Combines all signals into a weighted **risk score**

---

## 📡 APIs Used

| API | Purpose | Free Tier |
|-----|---------|-----------|
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | Scan URLs against 70+ security engines | 500 requests/day |
| [URLScan.io](https://urlscan.io/docs/api/) | Visual page analysis & screenshots | 100 requests/day |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Python 3.11, Flask |
| HTTP Client | Python `requests` library |
| Email Parsing | Python `email` standard library |
| API Integration | VirusTotal v3 REST API |
| CORS | Flask-CORS |

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.8+
- A free [VirusTotal API key](https://www.virustotal.com/gui/my-apikey)

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/email-url-threat-analyzer.git
cd email-url-threat-analyzer
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Set your API key
Create a `.env` file in the project root:
```
VIRUSTOTAL_API_KEY=your_key_here
```

### 4. Run the backend
```bash
cd backend
python app.py
```
Server starts at `http://localhost:5000`

### 5. Open the frontend
Open `frontend/index.html` in your browser.  
The frontend auto-detects if the backend is offline and falls back to **demo mode**.

---

## 📁 Project Structure

```
email-url-threat-analyzer/
├── frontend/
│   ├── index.html          # UI layout and structure
│   ├── style.css           # Dark terminal-themed styling
│   └── script.js           # API calls, result rendering, scan history
├── backend/
│   ├── app.py              # Flask server with /api/analyze-url and /api/analyze-email
│   ├── url_checker.py      # VirusTotal API integration and threat scoring
│   └── email_checker.py    # Header parsing, domain checks, URL extraction
├── requirements.txt        # Python dependencies
└── README.md
```

---

## 🧠 Key Concepts Demonstrated

- **REST API integration** — calling third-party security APIs and handling JSON responses
- **Email header forensics** — understanding SPF, DKIM, and sender spoofing techniques
- **Threat scoring algorithms** — weighing multiple signals into a single risk score
- **Frontend-backend communication** — using `fetch()` with POST requests and CORS
- **Regex-based URL extraction** — pattern matching for threat hunting
- **Social engineering awareness** — detecting manipulation language in emails

---

## 🔮 Future Improvements

- [ ] Add [AbuseIPDB](https://www.abuseipdb.com/api) for IP reputation checks
- [ ] Support `.eml` file uploads for email analysis
- [ ] Add URLScan.io screenshot display for scanned URLs
- [ ] Add a database to store scan history persistently
- [ ] Build a browser extension version

---

## ⚠️ Disclaimer

This tool is built for **educational purposes** as a cybersecurity portfolio project. Do not use it to scan URLs or emails without authorization. Always respect the terms of service of any API you use.

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

*Built as a cybersecurity portfolio project to demonstrate threat intelligence API integration, email forensics, and full-stack web development skills.*
