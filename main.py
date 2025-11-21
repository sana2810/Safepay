from flask import Flask, render_template, request
from cryptography.fernet import Fernet
import hashlib
import rsa
import pandas as pd
from datetime import datetime
from time import time

app = Flask(__name__)

# ----------------------------
# Failed Attempt Tracking (3 attempts → 1 min lockout)
# ----------------------------
failed_attempts = {}   # {client_id: {"count": x, "lockout": timestamp}}
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 60  # seconds

# ----------------------------
# Load dataset
# ----------------------------
df = pd.read_csv(r"C:\Users\sana2\Downloads\transactions_small.csv")

# ----------------------------
# Normalize dataset columns
# ----------------------------
df['card_number'] = df['card_number'].astype(str).str.replace(" ", "")
df['cvv'] = df['cvv'].astype(str).str.strip()
df['card_type'] = df['card_type'].astype(str).str.strip().str.lower()

def normalize_expiry(exp):
    try:
        month, year = exp.split('/')
        if len(year) == 4:
            year = year[-2:]
        return f"{month}/{year}"
    except:
        return exp

df['expires'] = df['expires'].astype(str).apply(normalize_expiry).str.strip()
print(df.head())

# ----------------------------
# Encryption Utilities
# ----------------------------
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

def encrypt_symmetric(data: str) -> str:
    return cipher.encrypt(data.encode()).decode()

def decrypt_symmetric(token: str) -> str:
    return cipher.decrypt(token.encode()).decode()

(public_key, private_key) = rsa.newkeys(512)

def encrypt_asymmetric(data: str) -> str:
    return rsa.encrypt(data.encode(), public_key).hex()

def decrypt_asymmetric(token_hex: str) -> str:
    token = bytes.fromhex(token_hex)
    return rsa.decrypt(token, private_key).decode()

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

# ----------------------------
# Routes
# ----------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    try:
        # Read form inputs
        client_id = int(request.form['client_id'])
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        phone = request.form['phone'].strip()
        amount = request.form['amount'].strip()
        card_number = request.form['card_number'].replace(" ", "")
        cvv = request.form['cvv'].strip()
        card_type = request.form['card_type'].strip().lower()
        expiry = normalize_expiry(request.form['expiry'].strip())

        # ----------------------------
        # Check Lockout Status (server-side enforcement)
        # ----------------------------
        now = time()
        if client_id in failed_attempts:
            info = failed_attempts[client_id]
            if info.get("count", 0) >= MAX_ATTEMPTS:
                # still locked?
                if now < info.get("lockout", 0):
                    remaining = int(info["lockout"] - now)
                    return render_template('failure.html',
                                           error=f"Too many failed attempts. Try again in {remaining} seconds.",
                                           locked=True,
                                           remaining=remaining)
                else:
                    # lockout expired -> reset
                    failed_attempts[client_id] = {"count": 0, "lockout": 0}

        # helper to register failure and return template with proper locked flag
        def register_failure(msg):
            failed_attempts.setdefault(client_id, {"count": 0, "lockout": 0})
            failed_attempts[client_id]["count"] += 1

            # If hits max, set lockout timestamp
            if failed_attempts[client_id]["count"] >= MAX_ATTEMPTS:
                failed_attempts[client_id]["lockout"] = time() + LOCKOUT_TIME
                remaining = int(failed_attempts[client_id]["lockout"] - time())
                return render_template('failure.html', error=msg, locked=True, remaining=remaining)

            # Not locked yet
            remaining = max(0, int(failed_attempts[client_id]["lockout"] - time())) if failed_attempts[client_id]["lockout"] else 0
            return render_template('failure.html', error=msg, locked=False, remaining=remaining)

        # ----------------------------
        # Validation & Matching
        # ----------------------------
        if client_id not in df['client_id'].values:
            return register_failure("Client ID not found.")

        record = df[df['client_id'] == client_id]

        if card_number not in record['card_number'].values:
            return register_failure("Invalid card number.")

        if cvv not in record['cvv'].values:
            return register_failure("Invalid CVV entered.")

        if expiry not in record['expires'].values:
            return register_failure("Card expired or invalid expiry date.")

        if card_type not in record['card_type'].values:
            return register_failure("Incorrect card type for this client.")

        match = df[
            (df['client_id'] == client_id) &
            (df['card_number'] == card_number) &
            (df['cvv'] == cvv) &
            (df['card_type'] == card_type) &
            (df['expires'] == expiry)
        ]

        if match.empty:
            return register_failure("Invalid payment details!")

        # ----------------------------
        # Reset attempts on successful payment
        # ----------------------------
        failed_attempts[client_id] = {"count": 0, "lockout": 0}

        # ----------------------------
        # Encryption & Hashing
        # ----------------------------
        encrypted_card_sym = encrypt_symmetric(card_number)
        encrypted_cvv_sym = encrypt_symmetric(cvv)
        encrypted_card_rsa = encrypt_asymmetric(card_number)
        encrypted_cvv_rsa = encrypt_asymmetric(cvv)
        card_hash = hash_data(card_number)
        cvv_hash = hash_data(cvv)

        print("✅ Payment verified and processed successfully!")
        print(f"Encrypted Card (Symmetric): {encrypted_card_sym}")
        print(f"Encrypted CVV (Symmetric): {encrypted_cvv_sym}")
        print(f"Encrypted Card (RSA): {encrypted_card_rsa}")
        print(f"Encrypted CVV (RSA): {encrypted_cvv_rsa}")
        print(f"Card Hash: {card_hash}")
        print(f"CVV Hash: {cvv_hash}")

        # ----------------------------
        # Generate Receipt Info
        # ----------------------------
        receipt_info = {
            "name": name,
            "client_id": client_id,
            "amount": amount,
            "card_last4": card_number[-4:],
            "date": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        }

        return render_template('success.html', **receipt_info)

    except Exception as e:
        print("Error:", str(e))
        # if exception occurs before client_id parsed, we can't check lock state; show generic failure
        return render_template('failure.html', error=str(e), locked=False, remaining=0)

if __name__ == '__main__':
    app.run(debug=True)
