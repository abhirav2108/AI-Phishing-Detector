import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle

# 1. Load the real dataset
df = pd.read_csv('dataset.csv')

# 2. Data Cleaning & Translation
df['is_phishing'] = df['Result'].apply(lambda x: 1 if x == -1 else 0)

X = df[['URL_Length', 'having_Sub_Domain', 'having_At_Symbol', 'SSLfinal_State']].copy()
X.columns = ['url_length', 'subdomains', 'has_at', 'is_https']

# --- 3. FIXING THE DATA LEAKAGE ---
# We inject pure random noise here. Now the AI cannot "cheat" by looking at 
# urgent_words. It is forced to study the actual URL columns to pass the test!
np.random.seed(42)
X['urgent_words'] = np.random.randint(0, 4, size=len(df)) 

y = df['is_phishing']

# 4. Split and Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"Training the Final AI Model on {len(X_train)} records...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. Evaluate the AI 
predictions = model.predict(X_test)
acc = accuracy_score(y_test, predictions) * 100

print(f"\n✅ Realistic Final Model Accuracy: {acc:.2f}%")

# 6. Save the final, corrected Brain
with open('phishing_model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("\nSuccess! The finalized AI brain is saved as 'phishing_model.pkl'.")