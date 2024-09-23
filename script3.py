import os
import requests
import pickle
import jwt
import ssl
import shutil

# Hardcoded secrets for secret scanning
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq..."

# Insecure deserialization (Pickle RCE)
def insecure_deserialization(data):
    return pickle.loads(data)  # Untrusted input, vulnerable to remote code execution!

# Insecure JWT handling (None algorithm attack)
def insecure_jwt_decode(token):
    return jwt.decode(token, options={"verify_signature": False})  # No signature verification!

# Insecure file upload (no validation or checks)
def upload_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    with open(f"/var/www/uploads/{os.path.basename(file_path)}", 'wb') as new_file:
        new_file.write(data)  # File uploaded directly without checks, vulnerable to path traversal

# Use of deprecated SSL methods (insecure communication)
def insecure_ssl_connection(hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # Using outdated SSLv3, vulnerable to POODLE attack!
    context.verify_mode = ssl.CERT_NONE  # No certificate verification!
    conn = context.wrap_socket(ssl.socket(), server_hostname=hostname)
    conn.connect((hostname, 443))
    return conn

# Path Traversal Vulnerability
def read_user_file(filename):
    with open(f"/var/www/files/{filename}", 'r') as f:
        return f.read()  # Vulnerable to directory traversal attacks!

# Insecure use of subprocess without sanitization
def run_unsafe_command(command):
    os.system(command)  # No input sanitization, vulnerable to command injection!

# Insecure use of JWT with hardcoded secret
def create_jwt_token(payload):
    token = jwt.encode(payload, "mysecretkey", algorithm="HS256")  # Hardcoded secret, weak JWT creation
    return token

# No rate-limiting on login function (Brute Force Vulnerability)
def login(username, password):
    if username == "admin" and password == "password123":
        return "Login successful!"
    else:
        return "Invalid credentials"  # No rate-limiting, vulnerable to brute force attacks!

# Unchecked use of shutil (Potential RCE)
def dangerous_file_move(src, dst):
    shutil.move(src, dst)  # No input validation, can be used to move sensitive files

# Buffer Overflow via poorly implemented file read
def read_config_file():
    buffer = bytearray(100)
    with open('/etc/config.txt', 'rb') as f:
        f.readinto(buffer)  # No bounds checking, may lead to buffer overflow if file is too large

# Insecure input for XML parsing (XXE vulnerability)
import xml.etree.ElementTree as ET
def parse_xml(user_input):
    tree = ET.fromstring(user_input)  # Vulnerable to XML External Entity (XXE) attacks

# Weak encryption practice (use of a static IV)
from Crypto.Cipher import AES
def encrypt_data(data):
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_CBC, iv=b'1234567890123456')  # Static IV, weak encryption!
    ciphertext = cipher.encrypt(data.ljust(16))
    return ciphertext

# Cross-Site Request Forgery (CSRF) vulnerability in API
def process_user_request(user_id, action):
    if action == 'delete':
        # No CSRF token check, vulnerable to CSRF attacks
        print(f"User {user_id} deleted from the system!")
    else:
        print(f"Action {action} performed for user {user_id}")
