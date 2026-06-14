from flask import Flask, request, jsonify
import pickle
import gzip
import re
import pandas as pd

app = Flask(__name__)

# 🧠 1. Load the Compressed AI Brain
print("Loading the Compressed AI Brain... ⏳")
try:
    with gzip.open('phishing_model.pkl.gz', 'rb') as file:
        model = pickle.load(file)
    print("✅ Massive AI Brain successfully loaded!")
except Exception as e:
    print("❌ Error loading model:", e)
    model = None

# 🔍 2. Feature Extraction (Exact same logic as main.py)
def extract_features(url):
    url_str = str(url)
    
    # Extracting the 6 mathematical clues
    url_length = len(url_str)
    has_at_symbol = 1 if '@' in url_str else 0
    dot_count = url_str.count('.')
    has_ip = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url_str) else 0
    hyphen_count = url_str.count('-')
    
    has_bad_words = 0
    bad_words = ['login', 'verify', 'update', 'free', 'secure', 'wallet']
    for word in bad_words:
        if word in url_str.lower():
            has_bad_words = 1
            break
            
    # Creating a DataFrame exactly like the training data
    features_df = pd.DataFrame(
        [[url_length, has_at_symbol, dot_count, has_ip, hyphen_count, has_bad_words]], 
        columns=['url_length', 'has_at_symbol', 'dot_count', 'has_ip', 'hyphen_count', 'has_bad_words']
    )
    
    return features_df

# 🌐 3. The API Endpoint for Chrome Extension
@app.route('/api/scan', methods=['POST'])
def scan_url():
    if not model:
        return jsonify({"error": "AI Model is offline"}), 500
        
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({"is_phishing": False, "error": "No URL provided"})
        
    try:
        # Extract features from the link
        features = extract_features(url)
        
        # Make the AI prediction (0 = Safe, 1 = Phishing)
        prediction = model.predict(features)[0]
        
        is_phishing = True if prediction == 1 else False
        
        return jsonify({"is_phishing": is_phishing, "url": url})
        
    except Exception as e:
        print("Prediction Error:", e)
        # Fallback security check if AI fails
        return jsonify({"is_phishing": False, "error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)