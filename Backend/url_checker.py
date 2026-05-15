import requests
import base64
import os
from datetime import datetime

# Get your free API key at: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_API_KEY_HERE')

def analyze_url(url: str) -> dict:
    """
    Analyzes a URL for threats using the VirusTotal API.

    How it works:
    1. VirusTotal requires URLs to be base64-encoded as their identifier
    2. We submit the URL to VT's scan endpoint
    3. We fetch the analysis report which contains verdicts from 70+ security engines
    4. We calculate a threat score based on how many engines flagged it

    Args:
        url: The URL string to analyze

    Returns:
        A dictionary with verdict, threat score, and details
    """

    # VirusTotal URL ID = base64url-encoded URL (no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        # Step 1: Submit URL for scanning
        submit_response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data=f'url={url}'
        )
        submit_response.raise_for_status()

        # Step 2: Fetch analysis results
        report_response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers
        )
        report_response.raise_for_status()

        report = report_response.json()
        stats = report['data']['attributes']['last_analysis_stats']

        malicious   = stats.get('malicious', 0)
        suspicious  = stats.get('suspicious', 0)
        harmless    = stats.get('harmless', 0)
        undetected  = stats.get('undetected', 0)
        total       = malicious + suspicious + harmless + undetected

        # Calculate threat score (0-100)
        threat_score = int(((malicious * 1.0) + (suspicious * 0.5)) / max(total, 1) * 100)

        # Determine verdict
        if malicious >= 5 or threat_score >= 50:
            verdict = 'DANGEROUS'
        elif malicious >= 1 or suspicious >= 3 or threat_score >= 20:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'SAFE'

        # Extract extra metadata
        attrs = report['data']['attributes']
        categories = list(attrs.get('categories', {}).values())
        category = categories[0] if categories else 'Unknown'

        # Domain age from creation date
        creation_ts = attrs.get('creation_date')
        if creation_ts:
            created = datetime.utcfromtimestamp(creation_ts)
            age_days = (datetime.utcnow() - created).days
            domain_age = f'{age_days} days' if age_days < 365 else f'{age_days // 365} years'
        else:
            domain_age = 'Unknown'

        return {
            'verdict':      verdict,
            'threat_score': threat_score,
            'malicious':    malicious,
            'suspicious':   suspicious,
            'total_engines': total,
            'category':     category,
            'domain_age':   domain_age,
            'https':        url.startswith('https'),
            'redirects':    str(len(attrs.get('redirection_chain', []))) + ' redirects'
        }

    except requests.exceptions.RequestException as e:
        return {
            'verdict':       'ERROR',
            'threat_score':  0,
            'malicious':     0,
            'suspicious':    0,
            'total_engines': 0,
            'category':      'API Error',
            'domain_age':    'Unknown',
            'https':         url.startswith('https'),
            'redirects':     'Unknown',
            'error':         str(e)
        }
