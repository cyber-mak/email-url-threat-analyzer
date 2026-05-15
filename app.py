from flask import Flask, request, jsonify
from flask_cors import CORS
from url_checker import analyze_url
from email_checker import analyze_email

app = Flask(__name__)
CORS(app)  # Allow requests from the frontend

@app.route('/api/analyze-url', methods=['POST'])
def url_scan():
    """
    Receives a URL from the frontend and returns a threat analysis report.
    """
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    result = analyze_url(url)
    return jsonify(result)


@app.route('/api/analyze-email', methods=['POST'])
def email_scan():
    """
    Receives raw email text from the frontend and returns a threat analysis report.
    """
    data = request.get_json()
    email_text = data.get('email', '').strip()

    if not email_text:
        return jsonify({'error': 'No email content provided'}), 400

    result = analyze_email(email_text)
    return jsonify(result)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
