import pandas as pd

csv_path = r"C:\Users\sana2\Downloads\cards_data.csv"
df = pd.read_csv(csv_path)

df = df.head(50)
df = df[['client_id', 'card_type', 'card_number', 'expires', 'cvv']]

# ----------------------------
# Normalize dataset columns
# ----------------------------
df['card_number'] = df['card_number'].astype(str).str.replace(" ", "")
df['cvv'] = df['cvv'].astype(str).str.strip()
df['card_type'] = df['card_type'].astype(str).str.strip().str.lower()
# Normalize expiry MM/YY
def normalize_expiry(exp):
    try:
        month, year = exp.split('/')
        if len(year) == 4:
            year = year[-2:]
        return f"{month}/{year}"
    except:
        return exp
df['expires'] = df['expires'].astype(str).apply(normalize_expiry).str.strip()

df.to_csv(r"C:\Users\sana2\Downloads\transactions_small.csv", index=False)
print("transactions_small.csv saved with normalized fields!")
