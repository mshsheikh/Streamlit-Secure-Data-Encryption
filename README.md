# Secure Data Encryption Tool

A simple Streamlit app for encrypting/decrypting data with password protection.

## Installation

```bash
git clone https://github.com/your-repo/encryption-app.git
cd encryption-app
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Usage

1. Run the app:
```bash
streamlit run app.py
```

2. Access at http://localhost:8501

3. Login with any username/password (demo mode)

4. Use the interface to:
   - Encrypt data with a passkey
   - Store encrypted data with unique IDs
   - Decrypt data using stored IDs and passkeys

## Important Notes

⚠️ This is a demonstration application ⚠️

- All data is stored temporarily in memory
- No real user accounts or persistent storage
- For educational purposes only
- Security features are basic and not production-ready
- Logout button clears your session

MIT License - Use at your own risk