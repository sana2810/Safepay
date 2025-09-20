import pandas as pd

# Load original large dataset
csv_path = r"C:\Samyah\datasets\cards_data.csv"
df = pd.read_csv(csv_path)

# Keep only first 50 rows and needed columns
df = df.head(50)
df = df[['client_id', 'card_type', 'card_number', 'expires', 'cvv']]

# ----------------------------
# Normalize dataset columns
# ----------------------------
# Clean card number: remove spaces
df['card_number'] = df['card_number'].astype(str).str.replace(" ", "")
# CVV as string
df['cvv'] = df['cvv'].astype(str).str.strip()
# Card type lowercase
df['card_type'] = df['card_type'].astype(str).str.strip().str.lower()
# Normalize expiry MM/YY
def normalize_expiry(exp):
    try:
        month, year = exp.split('/')
        if len(year) == 4:
            year = year[-2:]  # last 2 digits
        return f"{month}/{year}"
    except:
        return exp
df['expires'] = df['expires'].astype(str).apply(normalize_expiry).str.strip()

# Save smaller CSV for Flask app
df.to_csv(r"C:\Samyah\datasets\transactions_small.csv", index=False)
print("transactions_small.csv saved with normalized fields!")
