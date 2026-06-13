import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

def is_phishing_url(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Rule 1: Direct IP Address catch karnara Trap 🕸️
        # Jar domain madhe numbers astil (ex. 192.168.1.1), tar direct danger!
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            return True
            
        # Rule 2: Danger Keywords Trap 🚨
        suspicious_words = ['login', 'verify', 'update', 'free', 'secure', 'account', 'bank']
        url_lower = url.lower()
        
        # Jar URL madhe he words astil, tar phishing asnyachi shakyata jast ahe
        word_count = sum(1 for word in suspicious_words if word in url_lower)
        if word_count >= 2: # Don kiva tyahun jast danger words aale tar block
            return True
            
        return False
    except Exception as e:
        print("Error analyzing URL:", e)
        return False

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url', '')
    
    # Check calling our strict function
    result = is_phishing_url(url)
    
    return jsonify({"is_phishing": result, "url": url})

if __name__ == '__main__':
    app.run(debug=True)
