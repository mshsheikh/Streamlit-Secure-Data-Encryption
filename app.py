import streamlit as st
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import time

# title and config.
st.set_page_config(page_title="Secure Data Encryption System", layout="centered")

# initialize session
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # Dictionary to store encrypted data
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = False
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_view' not in st.session_state:
    st.session_state.current_view = 'login'

# fixed
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 30  # sec.

# Function to derive a key from a password
def get_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Function to encrypt data
def encrypt_data(data, password):
    key, salt = get_key_from_password(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data, salt

# Function to decrypt data
def decrypt_data(encrypted_data, password, salt):
    try:
        key, _ = get_key_from_password(password, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        return decrypted_data, True
    except Exception:
        return "", False

# Function to verify the passkey
def verify_passkey(data_id, passkey):
    if data_id not in st.session_state.stored_data:
        return False
    
    encrypted_data = st.session_state.stored_data[data_id]['encrypted_data']
    salt = st.session_state.stored_data[data_id]['salt']
    
    _, success = decrypt_data(encrypted_data, passkey, salt)
    return success

# Function to handle login
def handle_login():
    st.title("Secure Data Encryption System")
    st.subheader("Login")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        # In a real system, this would validate against stored credentials
        # For demo purposes, we'll accept any non-empty username/password
        if username and password:
            st.session_state.authenticated = True
            st.session_state.current_view = 'main'
            st.rerun()
        else:
            st.error("Invalid username or password. Please try again.")

# Function to handle lockout
def handle_lockout():
    current_time = time.time()
    remaining_time = max(0, st.session_state.locked_until - current_time)
    
    st.title("Security Lockout")
    st.error(f"Too many failed attempts. System locked for {int(remaining_time)} seconds.")
    
    if remaining_time <= 0:
        st.session_state.locked_out = False
        st.session_state.failed_attempts = 0
        st.session_state.authenticated = False
        st.session_state.current_view = 'login'
        
        if st.button("Return to Login"):
            st.rerun()

# Function to handle main application view
def handle_main_view():
    st.title("Secure Data Encryption System")
    
    tab1, tab2 = st.tabs(["Encrypt Data", "Decrypt Data"])
    
    with tab1:
        st.subheader("Encrypt Your Data")
        data_id = st.text_input("Create Data ID (will be used for retrieval)", key="encrypt_id")
        user_data = st.text_area("Enter the data to encrypt", key="encrypt_data")
        passkey = st.text_input("Create a secure passkey", type="password", key="encrypt_passkey")
        confirm_passkey = st.text_input("Confirm passkey", type="password", key="confirm_passkey")
        
        if st.button("Encrypt and Store"):
            if not data_id or not user_data or not passkey:
                st.error("All fields are required.")
            elif passkey != confirm_passkey:
                st.error("Passkeys do not match.")
            elif data_id in st.session_state.stored_data:
                st.error("Data ID already exists. Please choose a different ID.")
            else:
                encrypted_data, salt = encrypt_data(user_data, passkey)
                st.session_state.stored_data[data_id] = {
                    'encrypted_data': encrypted_data,
                    'salt': salt
                }
                st.success(f"Data encrypted and stored with ID: {data_id}")
                st.info("Remember your passkey! It cannot be recovered if lost.")
    
    with tab2:
        st.subheader("Decrypt Your Data")
        data_id = st.text_input("Enter Data ID", key="decrypt_id")
        passkey = st.text_input("Enter passkey", type="password", key="decrypt_passkey")
        
        if st.button("Decrypt"):
            if not data_id or not passkey:
                st.error("All fields are required.")
            elif data_id not in st.session_state.stored_data:
                st.error("Data ID not found.")
            else:
                encrypted_data = st.session_state.stored_data[data_id]['encrypted_data']
                salt = st.session_state.stored_data[data_id]['salt']
                
                decrypted_data, success = decrypt_data(encrypted_data, passkey, salt)
                
                if success:
                    st.success("Data decrypted successfully!")
                    st.text_area("Decrypted Data", value=decrypted_data, height=200)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    
                    if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                        st.session_state.locked_out = True
                        st.session_state.locked_until = time.time() + LOCKOUT_DURATION
                        st.session_state.current_view = 'lockout'
                        st.rerun()
                    else:
                        attempts_left = MAX_FAILED_ATTEMPTS - st.session_state.failed_attempts
                        st.error(f"Incorrect passkey. {attempts_left} attempts remaining before lockout.")
    
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.current_view = 'login'
        st.rerun()

# Main app flow
if st.session_state.locked_out:
    handle_lockout()
elif not st.session_state.authenticated:
    handle_login()
else:
    handle_main_view()

# Display the current stored data IDs (just the IDs, not the data)
if st.session_state.authenticated and st.session_state.current_view == 'main':
    st.sidebar.header("Stored Data IDs")
    if st.session_state.stored_data:
        for data_id in st.session_state.stored_data:
            st.sidebar.text(f"• {data_id}")
    else:
        st.sidebar.text("No data stored yet")