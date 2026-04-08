import streamlit as st
import pandas as pd
import pickle
from urllib.parse import urlparse
import email
from email import policy

# --- 1. Load the AI Brain ---
try:
    with open('phishing_model.pkl', 'rb') as file:
        model = pickle.load(file)
except FileNotFoundError:
    st.error("Model file not found! Please run train.py first.")
    st.stop()

# --- 2. Sidebar Navigation & Credits ---
st.sidebar.title("Navigation")
analysis_mode = st.sidebar.radio("What do you want to analyze?", ["Analyze a URL", "Analyze an Email (.eml)"])

st.sidebar.divider()
st.sidebar.write("### Project Info")
st.sidebar.info(
    "**Developed by:** [Bhumi Verma]\n\n"
    "**Course:** [BCA]\n\n"
    "**Version:** 1.0 (AI Powered)"
)

# --- 3. Main UI Setup ---
st.title("🛡️ AI Phishing & Threat Detector")
st.write(f"**Current Mode:** {analysis_mode}")
st.divider()

# Default feature values
url_length, subdomains, has_at_val, is_https_val, urgent_words = 0, 0, 0, 1, 0
threat_factors = [] 

# ==========================================
# MODE 1: URL ANALYSIS
# ==========================================
if analysis_mode == "Analyze a URL":
    url_input = st.text_input("🔗 Paste Suspicious URL here:", placeholder="e.g., https://secure-login.bank.com/update")
    
    if st.button("Analyze URL", type="primary") and url_input != "":
        # Feature Extraction
        url_length = len(url_input)
        is_https_val = 1 if url_input.lower().startswith("https") else 0
        has_at_val = 1 if "@" in url_input else 0
        
        domain = urlparse(url_input).netloc
        if domain == "":
            domain = urlparse("http://" + url_input).netloc
        subdomains = max(0, domain.count('.') - 1)
        
        # Display Extracted Metrics to the User
        st.write("### Extracted URL Features:")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Length", url_length)
        col2.metric("Subdomains", subdomains)
        col3.metric("HTTPS", "Yes" if is_https_val == 1 else "No")
        col4.metric("'@' Symbol", "Yes" if has_at_val == 1 else "No")
        
        # Build Threat Factors for the Assessment report
        if url_length > 75: threat_factors.append("- **Excessive Length:** Phishing URLs are often long to hide the real domain.")
        if subdomains > 2: threat_factors.append("- **Multiple Subdomains:** Used to mimic legitimate sites (e.g., login.apple.scam.com).")
        if has_at_val == 1: threat_factors.append("- **'@' Symbol Used:** This forces the browser to ignore everything before the @, a common trick.")
        if is_https_val == 0: threat_factors.append("- **No SSL (HTTP):** Legitimate corporate sites rarely use unencrypted HTTP connections.")

# ==========================================
# MODE 2: EMAIL ANALYSIS (.eml import)
# ==========================================
elif analysis_mode == "Analyze an Email (.eml)":
    st.info("💡 **Pro Tip:** In Gmail, open an email, click the 3 vertical dots (top right), and select 'Download message' to get an .eml file.")
    uploaded_file = st.file_uploader("📥 Drag and drop your .eml file here", type=["eml"])
    
    if uploaded_file is not None:
        # Parse the email file using Python's built-in email library
        msg = email.message_from_bytes(uploaded_file.getvalue(), policy=policy.default)
        
        subject = msg['subject']
        sender = msg['from']
        
        # Extract the body text
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode()
        else:
            body = msg.get_payload(decode=True).decode()
            
        st.write("### 📧 Email Metadata Extracted:")
        st.write(f"**From:** {sender}")
        st.write(f"**Subject:** {subject}")
        
        # Automatically count urgent keywords in the email body
        urgent_list = ['urgent', 'immediate', 'suspended', 'verify', 'password', 'action required']
        body_lower = body.lower()
        urgent_words = sum(body_lower.count(word) for word in urgent_list)
        
        st.metric("Suspicious Keywords Found", urgent_words)
        
        if urgent_words > 0:
            threat_factors.append(f"- **High-Pressure Language:** The AI found {urgent_words} trigger words (like 'urgent' or 'verify') designed to cause panic.")
            
        # For the prototype, we set URL features to "safe" defaults when checking an email
        is_https_val = 1 
        
        if st.button("Run AI on Email", type="primary"):
            pass # Continues to the AI block below

# ==========================================
# FINAL AI EXECUTION & THREAT ASSESSMENT
# ==========================================
# We only run the AI if a button was pressed and data was collected
if (analysis_mode == "Analyze a URL" and 'url_input' in locals() and url_input != "") or \
   (analysis_mode == "Analyze an Email (.eml)" and 'uploaded_file' in locals() and uploaded_file is not None):
    
    # --- THE TRANSLATION LAYER FOR THE AI ---
    # 1. Translate Length (UCI Rules)
    if url_length < 54:
        ai_length = 1
    elif url_length <= 75:
        ai_length = 0
    else:
        ai_length = -1
        
    # 2. Translate Subdomains (UCI Rules)
    if subdomains <= 1:
        ai_sub = 1
    elif subdomains == 2:
        ai_sub = 0
    else:
        ai_sub = -1
        
    # 3. Translate '@' Symbol & HTTPS (UCI Rules)
    ai_at = -1 if has_at_val == 1 else 1
    ai_https = 1 if is_https_val == 1 else -1

    # --- PACK TRANSLATED DATA FOR AI ---
    input_data = pd.DataFrame({
        'url_length': [ai_length],
        'subdomains': [ai_sub],
        'has_at': [ai_at],
        'is_https': [ai_https],
        'urgent_words': [urgent_words]
    })

    # AI Prediction
    prediction = model.predict(input_data)[0]
    probabilities = model.predict_proba(input_data)[0]
    phishing_probability = probabilities[1] * 100 
    
    st.divider()
    st.header("📊 Final Threat Assessment")
    st.progress(phishing_probability / 100)
    
    if prediction == 1:
        st.error(f"🚨 **VERDICT: PHISHING DETECTED** ({phishing_probability:.1f}% Confidence)")
        st.write("### Why the AI flagged this:")
        if len(threat_factors) > 0:
            for factor in threat_factors:
                st.write(factor)
        else:
            st.write("- The overall structure matched known malicious patterns in the training data.")
    else:
        st.success(f"✅ **VERDICT: SAFE** ({phishing_probability:.1f}% Phishing Probability)")
        st.write("The AI did not detect significant structural anomalies associated with phishing.")