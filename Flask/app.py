from flask import Flask, render_template, request, redirect, url_for, flash, session
import hashlib
import json
from web3 import Web3, HTTPProvider
import ipfshttpclient
import os
import sqlite3
from datetime import datetime

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Set up file upload folder
UPLOAD_FOLDER = 'uploaded_evidence'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize SQLite database
db = sqlite3.connect("evidence.db", check_same_thread=False)
cursor = db.cursor()

# Create tables if they don't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, 
    password TEXT, 
    role TEXT
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)''')

db.commit()

# Blockchain and IPFS setup
blockchain_address = 'http://127.0.0.1:7545'
web3 = Web3(HTTPProvider(blockchain_address))

try:
    client = ipfshttpclient.connect()
    print("Connected to IPFS")
except Exception as e:
    print(f"Error: Unable to connect to IPFS - {e}")
    exit()

# Smart contract configuration
contract_path = 'C:/Users/chinm/Desktop/Newfolder3/build/contracts/Evidence.json'
contract_address = '0xb689304009555EBADc74d70Fb44fcdFb296d7c2f'

try:
    with open(contract_path) as file:
        contract_json = json.load(file)
        contract_abi = contract_json['abi']
        contract = web3.eth.contract(address=contract_address, abi=contract_abi)
        print("Smart Contract Loaded Successfully")
except FileNotFoundError:
    print(f"Error: {contract_path} file not found.")
    exit()

# Set the default blockchain account
web3.eth.default_account = web3.eth.accounts[0]

# Helper Functions
def log_action(username, action):
    cursor.execute("INSERT INTO logs (username, action) VALUES (?, ?)", (username, action))
    db.commit()

def verify_user(username, password, role):
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result and result[0] == hashlib.sha256(password.encode()).hexdigest() and result[1] == role:
        return True
    return False

def fetch_all_logs():
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    return cursor.fetchall()

# Seed admin user
cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
               ("admin", hashlib.sha256("adminpass".encode()).hexdigest(), "admin"))
db.commit()

# Routes
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_action():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    if verify_user(username, password, role):
        session['username'] = username
        session['role'] = role
        log_action(username, f"Logged in as {role}")
        return redirect(url_for(f'{role}_dashboard'))
    else:
        flash("Invalid credentials or role", 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    if 'username' in session:
        log_action(session['username'], "Logged out")
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') == 'admin':
        logs = fetch_all_logs()
        return render_template('admin_dashboard.html', logs=logs)
    return redirect(url_for('login'))

@app.route('/police_dashboard')
def police_dashboard():
    if session.get('role') == 'police':
        logs = fetch_all_logs()
        return render_template('police_dashboard.html', logs=logs)
    return redirect(url_for('login'))

@app.route('/forensic_dashboard')
def forensic_dashboard():
    if session.get('role') == 'forensic':
        logs = fetch_all_logs()
        return render_template('forensic_dashboard.html', logs=logs)
    return redirect(url_for('login'))

@app.route('/court_dashboard')
def court_dashboard():
    if session.get('role') == 'court':
        logs = fetch_all_logs()
        return render_template('court_dashboard.html', logs=logs)
    return redirect(url_for('login'))

@app.route('/upload_evidence', methods=['POST'])
def upload_evidence():
    evID = int(request.form['evID'])
    evOwner = request.form['evOwner']
    evLocation = request.form['evLocation']

    # Check if a file is uploaded
    file = request.files.get('evFile')
    if not file or file.filename == '':
        flash("No file selected for uploading", 'error')
        return redirect(url_for(f'{session["role"]}_dashboard'))

    # Save file locally
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    flash(f"File uploaded successfully: {file.filename}", 'success')

    # Upload file to IPFS
    try:
        res = client.add(filepath)
        evCID = res['Hash']
    except Exception as e:
        flash(f"Error uploading file to IPFS: {e}", 'error')
        return redirect(url_for(f'{session["role"]}_dashboard'))

    # Add evidence to blockchain
    try:
        tx_hash = contract.functions.addEvidence(evID, file.filename, evOwner, evLocation, evCID).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)
        flash("Evidence Uploaded Successfully", 'success')
        log_action(session['username'], f"Uploaded evidence with ID {evID}")
    except Exception as e:
        flash(f"Error uploading evidence to blockchain: {e}", 'error')

    return redirect(url_for(f'{session["role"]}_dashboard'))
@app.route('/verify_evidence', methods=['POST'])
def verify_evidence():
    evID = int(request.form['evID'])
    try:
        myEvidence = contract.functions.getEvidence(evID).call()
        evidence_details = {
            "evid": evID,  # Include Evidence ID
            "Name": myEvidence[0],
            "Owner": myEvidence[1],
            "Location": myEvidence[2],
            "Hash": myEvidence[3],
            "Timestamp": datetime.utcfromtimestamp(myEvidence[4]).strftime('%Y-%m-%d %H:%M:%S'),  # Convert Unix timestamp
        }
        log_action(session['username'], f"Viewed evidence with ID {evID}")
        return render_template('viewevidence.html', evidence_details=evidence_details)
    except Exception as e:
        flash(f"Error fetching evidence: {e}", 'error')
        return redirect(url_for(f'{session["role"]}_dashboard'))

@app.route('/admin_add_user', methods=['POST'])
def admin_add_user():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        db.commit()
        flash("User added successfully", 'success')
        log_action(session['username'], f"Added user {username} with role {role}")
    except sqlite3.IntegrityError:
        flash("User already exists", 'error')

    return redirect(url_for('admin_dashboard'))

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
