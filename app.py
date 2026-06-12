from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pickle
import gzip  # 🔥 HI NAVIN LINE ADD KAR
import whois
import urllib.parse
# ... (baki tuze imports)
from datetime import datetime

app = Flask(__name__)
CORS(app) # Open the door for the extension!

print("Loading the AI Brain...")
# Load the compressed model
with gzip.open('phishing_model.pkl.gz', 'rb') as f:
    model = pickle.load(f)

def scan_words(url):
    bad_words = ['login', 'verify', 'update', 'free', 'wallet', 'irctc', 'refund', 'jio-free', 'kyc', 'aadhar', 'pan-update', 'ipl-vip']
    for word in bad_words:
        if word in str(url).lower():
            return 1 
    return 0 

def check_domain_age(url):
    try:
        domain = urllib.parse.urlparse(url).netloc
        if not domain:
            domain = url
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if type(creation_date) is list:
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age
        return 999 
    except:
        return 999 

session_stats = {"total_scans": 0, "safe_caught": 0, "phishing_caught": 0}

@app.route('/')
def home():
    return render_template('index.html', result="", warning="", stats=session_stats)

@app.route('/check', methods=['POST'])
def check():
    user_link = request.form['url_input']
    session_stats["total_scans"] += 1
    
    test_clues = [[len(user_link), 1 if '@' in user_link else 0, user_link.count('.'), 1 if re.search(r'\d+\.\d+\.\d+\.\d+', user_link) else 0, user_link.count('-'), scan_words(user_link)]]
    prediction = model.predict(test_clues)
    domain_age_days = check_domain_age(user_link)
    
    age_warning = ""
    if domain_age_days < 30:
        age_warning = f"🚨 RED FLAG: This website is only {domain_age_days} days old!"
        
    if prediction[0] == 1 or domain_age_days < 30:
        session_stats["phishing_caught"] += 1
        return render_template('index.html', result="⚠️ PHISHING DETECTED", warning=age_warning, stats=session_stats)
    else:
        session_stats["safe_caught"] += 1
        return render_template('index.html', result="🟢 SAFE LINK", warning="", stats=session_stats)

# --- SPRINT 3: NEW CHROME EXTENSION API ---
@app.route('/api/scan', methods=['POST', 'OPTIONS'])
def api_scan():
    # The extension will send data in JSON format
    data = request.get_json()
    user_link = data.get('url')
    
    test_clues = [[len(user_link), 1 if '@' in user_link else 0, user_link.count('.'), 1 if re.search(r'\d+\.\d+\.\d+\.\d+', user_link) else 0, user_link.count('-'), scan_words(user_link)]]
    prediction = model.predict(test_clues)
    domain_age_days = check_domain_age(user_link)
    
    is_phishing = False
    if prediction[0] == 1 or domain_age_days < 30:
        is_phishing = True
        
    # Return pure data, no HTML!
    return jsonify({
        "url": user_link,
        "is_phishing": is_phishing
    })

if __name__ == '__main__':
    app.run(debug=True)