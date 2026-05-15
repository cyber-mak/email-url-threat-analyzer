import re
import email as email_lib
from url_checker import analyze_url

# Keywords commonly found in phishing emails
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'verify', 'suspended', 'confirm',
    'click here', 'limited time', 'act now', 'account locked',
    'password expired', 'unusual activity', 'update your information',
    'validate', 'your account has been'
]

# File extensions that are suspicious in email attachments
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.js', '.zip', '.rar', '.scr', '.cmd']


def analyze_email(raw_email: str) -> dict:
    """
    Analyzes raw email text for phishing indicators.

    How it works:
    1. Parse headers: extract sender, Reply-To, and check for domain mismatch
       (a common trick — display name says "PayPal" but email is from random-domain.com)
    2. Check SPF/DKIM: these appear in headers when email servers authenticate the message
    3. Extract all URLs from the email body using regex
    4. Scan each extracted URL through VirusTotal
    5. Check for urgency/manipulation language
    6. Check for suspicious attachment types
    7. Calculate an overall risk score

    Args:
        raw_email: Full email text including headers

    Returns:
        Dictionary with verdict, risk score, and detailed findings
    """

    risk_score = 0
    findings = []

    # ── STEP 1: Parse email headers ──
    try:
        msg = email_lib.message_from_string(raw_email)
    except Exception:
        msg = None

    sender = _extract_sender(msg, raw_email)
    domain_match = _check_domain_match(msg, raw_email)
    spf, dkim = _check_auth_headers(msg, raw_email)

    if not domain_match:
        risk_score += 35
        findings.append('Sender domain does not match Reply-To (possible spoofing)')

    if spf == 'FAIL':
        risk_score += 20
        findings.append('SPF check failed — email may not be from claimed sender')

    if dkim == 'NONE':
        risk_score += 10
        findings.append('No DKIM signature found')

    # ── STEP 2: Extract URLs from body ──
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    extracted_urls = re.findall(url_pattern, raw_email)
    extracted_urls = list(set(extracted_urls))[:5]  # Deduplicate, limit to 5

    malicious_url_count = 0
    for url in extracted_urls:
        result = analyze_url(url)
        if result.get('verdict') in ('DANGEROUS', 'SUSPICIOUS'):
            malicious_url_count += 1

    if malicious_url_count > 0:
        risk_score += min(malicious_url_count * 20, 40)
        findings.append(f'{malicious_url_count} malicious/suspicious URL(s) found in body')

    # ── STEP 3: Urgency and manipulation keywords ──
    lower_text = raw_email.lower()
    found_keywords = [kw for kw in URGENCY_KEYWORDS if kw in lower_text]

    if len(found_keywords) >= 3:
        risk_score += 20
    elif len(found_keywords) >= 1:
        risk_score += 10

    # ── STEP 4: Suspicious attachments ──
    suspicious_attachments = any(ext in lower_text for ext in SUSPICIOUS_EXTENSIONS)
    if suspicious_attachments:
        risk_score += 15
        findings.append('Suspicious attachment extension detected')

    # ── STEP 5: Cap score and determine verdict ──
    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        verdict = 'PHISHING'
    elif risk_score >= 25:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'SAFE'

    return {
        'verdict':                verdict,
        'risk_score':             risk_score,
        'sender':                 sender,
        'domain_match':           domain_match,
        'spf':                    spf,
        'dkim':                   dkim,
        'urgency_keywords':       found_keywords,
        'suspicious_attachments': suspicious_attachments,
        'extracted_urls':         extracted_urls,
        'findings':               findings
    }


# ── HELPER FUNCTIONS ──

def _extract_sender(msg, raw_text: str) -> str:
    """Extract the From header from a parsed email or raw text."""
    if msg:
        return msg.get('From', 'Unknown')
    match = re.search(r'^From:\s*(.+)$', raw_text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else 'Unknown'


def _check_domain_match(msg, raw_text: str) -> bool:
    """
    Check if the From domain matches the Reply-To domain.
    Phishing emails often spoof the display name but use a different actual domain.
    """
    def extract_domain(address: str) -> str:
        match = re.search(r'@([\w.-]+)', address or '')
        return match.group(1).lower() if match else ''

    if msg:
        from_addr    = msg.get('From', '')
        reply_to     = msg.get('Reply-To', '')
    else:
        from_match   = re.search(r'^From:\s*(.+)$', raw_text, re.MULTILINE | re.IGNORECASE)
        reply_match  = re.search(r'^Reply-To:\s*(.+)$', raw_text, re.MULTILINE | re.IGNORECASE)
        from_addr    = from_match.group(1) if from_match else ''
        reply_to     = reply_match.group(1) if reply_match else ''

    if not reply_to:
        return True  # No Reply-To header = not an indicator

    from_domain  = extract_domain(from_addr)
    reply_domain = extract_domain(reply_to)

    return from_domain == reply_domain


def _check_auth_headers(msg, raw_text: str) -> tuple:
    """
    Extract SPF and DKIM pass/fail status from Received-SPF and Authentication-Results headers.
    These headers are added by receiving mail servers.
    """
    text = raw_text.lower()

    # SPF check
    if 'received-spf: pass' in text or 'spf=pass' in text:
        spf = 'PASS'
    elif 'received-spf: fail' in text or 'spf=fail' in text:
        spf = 'FAIL'
    elif 'spf=softfail' in text or 'received-spf: softfail' in text:
        spf = 'SOFTFAIL'
    else:
        spf = 'NONE'

    # DKIM check
    if 'dkim=pass' in text:
        dkim = 'PASS'
    elif 'dkim=fail' in text:
        dkim = 'FAIL'
    else:
        dkim = 'NONE'

    return spf, dkim
