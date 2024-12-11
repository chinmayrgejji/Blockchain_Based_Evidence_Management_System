import tkinter as tk
from tkinter import messagebox
import hashlib
import json
from web3 import Web3, HTTPProvider
import ipfshttpclient
import os
import subprocess

# Dictionary to store usernames, passwords, and roles (this can be replaced by a database for production)
users = {
    "admin": {"password": hashlib.sha256("adminpass".encode()).hexdigest(), "role": "admin"},
    "police1": {"password": hashlib.sha256("policepass".encode()).hexdigest(), "role": "police"},
    "forensic1": {"password": hashlib.sha256("forensicpass".encode()).hexdigest(), "role": "forensic"},
    "court1": {"password": hashlib.sha256("courtpass".encode()).hexdigest(), "role": "court"},
}

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
ChainContract = 'build/contracts/Evidence.json'
ChainAddress = '0x52d028bCAA02f1d83956571a52b6554697833108'

try:
    with open(ChainContract) as file1:
        contract_json1 = json.load(file1)
        contract_abi1 = contract_json1['abi']
        contract1 = web3.eth.contract(address=ChainAddress, abi=contract_abi1)
        print("Smart Contract Loaded Successfully")
except FileNotFoundError:
    print(f"Error: {ChainContract} file not found.")
    exit()

web3.eth.default_account = web3.eth.accounts[0]


# Function to hash password and verify
def verify_user(username, password, role):
    if username in users:
        stored_password = users[username]["password"]
        if stored_password == hashlib.sha256(password.encode()).hexdigest() and users[username]["role"] == role:
            return True
    return False


# Function for the login screen
def login_screen():
    login_window = tk.Tk()
    login_window.title("Evidence Management System - Login")

    tk.Label(login_window, text="Username:").grid(row=0, column=0, padx=10, pady=10)
    username_entry = tk.Entry(login_window)
    username_entry.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(login_window, text="Password:").grid(row=1, column=0, padx=10, pady=10)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(login_window, text="Role:").grid(row=2, column=0, padx=10, pady=10)
    role_combobox = tk.StringVar(value="police")
    roles = ["police", "forensic", "court"]
    role_menu = tk.OptionMenu(login_window, role_combobox, *roles)
    role_menu.grid(row=2, column=1, padx=10, pady=10)

    def login_action():
        username = username_entry.get()
        password = password_entry.get()
        role = role_combobox.get()

        if verify_user(username, password, role):
            login_window.destroy()
            if role == "admin":
                admin_dashboard()
            elif role == "police":
                police_dashboard()
            elif role == "forensic":
                forensic_dashboard()
            elif role == "court":
                court_dashboard()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials or role.")

    login_button = tk.Button(login_window, text="Login", command=login_action)
    login_button.grid(row=3, columnspan=2, pady=20)

    login_window.mainloop()


# Dashboard for Police
def police_dashboard():
    dashboard_window = tk.Tk()
    dashboard_window.title("Police Dashboard")

    tk.Label(dashboard_window, text="Police Dashboard - Evidence Management").pack(pady=20)
    tk.Button(dashboard_window, text="Upload Evidence", command=upload_evidence).pack(pady=10)
    tk.Button(dashboard_window, text="Verify Evidence", command=verify_evidence).pack(pady=10)
    tk.Button(dashboard_window, text="Exit", command=dashboard_window.quit).pack(pady=10)

    dashboard_window.mainloop()


# Dashboard for Forensic
def forensic_dashboard():
    dashboard_window = tk.Tk()
    dashboard_window.title("Forensic Dashboard")

    tk.Label(dashboard_window, text="Forensic Dashboard - Evidence Management").pack(pady=20)
    tk.Button(dashboard_window, text="Upload Evidence", command=upload_evidence).pack(pady=10)
    tk.Button(dashboard_window, text="Verify Evidence", command=verify_evidence).pack(pady=10)
    tk.Button(dashboard_window, text="Exit", command=dashboard_window.quit).pack(pady=10)

    dashboard_window.mainloop()


# Dashboard for Court
def court_dashboard():
    dashboard_window = tk.Tk()
    dashboard_window.title("Court Dashboard")

    tk.Label(dashboard_window, text="Court Dashboard - Evidence Management").pack(pady=20)
    tk.Button(dashboard_window, text="Verify Evidence", command=verify_evidence).pack(pady=10)
    tk.Button(dashboard_window, text="Exit", command=dashboard_window.quit).pack(pady=10)

    dashboard_window.mainloop()


# Admin Dashboard
def admin_dashboard():
    admin_window = tk.Tk()
    admin_window.title("Admin Dashboard")

    tk.Label(admin_window, text="Admin Dashboard - Manage Users").pack(pady=20)

    def add_user():
        add_user_window = tk.Toplevel(admin_window)
        add_user_window.title("Add New User")

        tk.Label(add_user_window, text="Username:").grid(row=0, column=0)
        new_username = tk.Entry(add_user_window)
        new_username.grid(row=0, column=1)

        tk.Label(add_user_window, text="Password:").grid(row=1, column=0)
        new_password = tk.Entry(add_user_window, show="*")
        new_password.grid(row=1, column=1)

        tk.Label(add_user_window, text="Role:").grid(row=2, column=0)
        new_role = tk.StringVar(value="police")
        role_menu = tk.OptionMenu(add_user_window, new_role, "police", "forensic", "court")
        role_menu.grid(row=2, column=1)

        def submit_user():
            username = new_username.get()
            password = new_password.get()
            role = new_role.get()
            users[username] = {"password": hashlib.sha256(password.encode()).hexdigest(), "role": role}
            messagebox.showinfo("Success", f"User {username} added successfully.")
            add_user_window.destroy()

        tk.Button(add_user_window, text="Add User", command=submit_user).grid(row=3, columnspan=2, pady=10)

    tk.Button(admin_window, text="Add New User", command=add_user).pack(pady=10)
    tk.Button(admin_window, text="Exit", command=admin_window.quit).pack(pady=10)

    admin_window.mainloop()


# Functions for Evidence Operations
def upload_evidence():
    print("Add New Evidence - ")

    # Collecting evidence details
    evID = int(input("Enter ID: "))
    evName = input("Enter Evidence File Name: ")
    command = f'C:/Users/chinm/Desktop/Newfolder(2)/Evidence"{evName}" -w'

    print(f"Executing Command: {command}")
    a = os.popen(command).readline().strip()
    print(f"Command Output: {a}")

    if "added " in a:
        evCID = a.replace("added ", "").strip()[:46]
        evOwner = input("Enter Evidence Owner: ")
        evLocation = input("Enter Evidence Location: ")

        # Adding evidence to the blockchain
        try:
            tx_hash = contract1.functions.addEvidence(
                evID,
                evName,
                evCID,
                evOwner,
                evLocation
            ).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print("Evidence Uploaded Successfully")
        except Exception as e:
            print(f"Error Uploading Evidence: {e}")
    else:
        print("Error: Unable to process evidence CID")


def verify_evidence():
    evID = int(input("Enter ID: "))
    try:
        myEvidence = contract1.functions.getEvidence(evID).call()
        myArray = ["Name", "Hash", "Owner", "Location"]

        for i, evidence_detail in enumerate(myEvidence):
            print(f"[*] Evidence {myArray[i]}: {evidence_detail}")
    except Exception as e:
        print(f"Error Fetching Evidence: {e}")


# Start the Login Screen
login_screen()
