import os
import sqlite3
import subprocess
import hashlib
import requests

# Hardcoded credentials and API keys (for secret scanning)
API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
SECRET_KEY = "supersecretpassword123"
DB_PASSWORD = "rootpassword"

# SQL Injection Vulnerability
def get_user_info(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # Vulnerable to SQL injection!
    result = cursor.fetchall()
    conn.close()
    return result

# Command Injection Vulnerability
def ping_server(server_ip):
    command = f"ping -c 4 {server_ip}"
    os.system(command)  # Vulnerable to command injection!

# Insecure Hashing Algorithm (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is weak!

# Insecure HTTP Request without SSL verification
def get_data(url):
    response = requests.get(url, verify=False)  # SSL verification is disabled!
    return response.text

# Hardcoded sensitive data
def connect_to_db():
    conn_str = f"mysql+pymysql://root:{DB_PASSWORD}@localhost/mydb"
    print(f"Connecting to database with: {conn_str}")
    return conn_str  # Database credentials are hardcoded

# Use of eval() with user input (Remote Code Execution)
def evaluate_user_input(input_string):
    eval(input_string)  # Dangerous! Can execute arbitrary code

# Usage of subprocess with shell=True (Command Injection)
def dangerous_subprocess(command):
    subprocess.run(command, shell=True)  # Vulnerable to command injection

# Insecure random number generation (cryptographically insecure)
import random
def generate_token():
    return random.random()  # Not suitable for cryptographic use

# Insecure file handling (predictable temporary file names)
def insecure_temp_file_handling():
    with open('/tmp/tempfile.txt', 'w') as temp_file:
        temp_file.write('Sensitive data here')  # Temp files in predictable location

# Weak regular expression (ReDoS vulnerability)
import re
def vulnerable_regex(input_string):
    pattern = re.compile(r'(a+)+')
    return pattern.match(input_string)  # Vulnerable to ReDoS

# Cross-Site Scripting (XSS) in web application
def generate_html(user_input):
    html = f"<html><body>Welcome, {user_input}</body></html>"  # XSS vulnerability!
    return html

# Insecure file permissions
def create_sensitive_file():
    with open('sensitive_file.txt', 'w') as f:
        f.write('Sensitive information')
    os.chmod('sensitive_file.txt', 0o777)  # World-writable permissions!
