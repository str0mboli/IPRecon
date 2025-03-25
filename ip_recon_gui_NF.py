import customtkinter as ctk
import re
import ipaddress
import requests
import pandas as pd
import os
import sys  # Added for PyInstaller compatibility
import webbrowser
import base64
import hashlib
from tabulate import tabulate
from tkinter import filedialog
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# Function to restart the program
def restart_program():
    status_label.configure(text="🔄 Restarting the program...", text_color="blue")
    app.update()  # Update the UI to show the restart message
    os.execl(sys.executable, sys.executable, *sys.argv)  # Restart the program
    
# Helper function for PyInstaller resources
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# CustomTkinter settings
ctk.set_appearance_mode("dark")  # Dark mode
ctk.set_default_color_theme("blue")  # Theme color

# Add these constants for encryption
API_KEY_FILE = "api_key.encrypted"

# Function to derive AES key from a password
def derive_key_from_password(password):
    # Use PBKDF2 to derive a 32-byte key from the password
    salt = b"IPRecon_Salt_2025"  # Use a fixed salt (can be improved by storing a unique salt per user)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)

# Function to encrypt data using AES
def encrypt_data_aes(data, password):
    key = derive_key_from_password(password)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode()

# Function to decrypt data using AES
def decrypt_data_aes(encrypted_data, password):
    key = derive_key_from_password(password)
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return decrypted_data.decode()

# Function to save API key (encrypted with user-provided password)
def save_api_key(api_key, password):
    encrypted_api_key = encrypt_data_aes(api_key, password)
    with open(API_KEY_FILE, "w") as f:
        f.write(encrypted_api_key)

# Function to load API key (decrypted with user-provided password)
def load_api_key(password):
    if os.path.exists(API_KEY_FILE):
        try:
            with open(API_KEY_FILE, "r") as f:
                encrypted_api_key = f.read()
            return decrypt_data_aes(encrypted_api_key, password)
        except Exception as e:
            print(f"Error decrypting API key: {e}")
            return None
    return None

def extract_unique_public_ips(text):
    # Comprehensive IPv4 pattern that validates numbers 0-255
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # Comprehensive IPv6 pattern including compressed notation
    ipv6_pattern = r'\b(?:' + \
        r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|' + \
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:|' + \
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' + \
        r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|' + \
        r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|' + \
        r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|' + \
        r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|' + \
        r'[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|' + \
        r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))\b'

    ipv4_matches = re.findall(ipv4_pattern, text)
    ipv6_matches = re.findall(ipv6_pattern, text)
    
    # Validate and filter IPs
    valid_ips = set()
    for ip in ipv4_matches + ipv6_matches:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                valid_ips.add(str(ip_obj))
        except ValueError:
            continue

    return sorted(valid_ips)

def check_ip_reputation(api_key, ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "IP Address": data.get("ipAddress", ip),
            "Total Reports": data.get("totalReports", "N/A"),
            "Abuse Score": data.get("abuseConfidenceScore", "N/A"),
            "Country": data.get("countryCode", "N/A"),
            "ISP": data.get("isp", "N/A"),
            "Domain": data.get("domain", "N/A"),
            "Usage Type": data.get("usageType", "N/A"),
            "Last Reported": data.get("lastReportedAt", "N/A"),
        }
    else:
        return {"IP Address": ip, "Error": f"Failed to fetch data (Code: {response.status_code})"}

def display_results(df):
    global current_results_df
    result_box.configure(state="normal")  
    result_box.delete("1.0", "end")  

    if df.empty:
        result_box.insert("1.0", "⚠️ No results found!\n")
        status_label.configure(text="⚠️ No results found!", text_color="orange")
        result_box.configure(state="disabled")
        save_csv_button.configure(state="disabled")  # Disable Save button if no results
        return

    table_text = tabulate(df, headers="keys", tablefmt="grid")

    result_box.insert("1.0", table_text)  
    result_box.configure(state="disabled")  

    status_label.configure(text="✅ IP check complete!", text_color="green")
    save_csv_button.configure(state="normal")  # Enable Save button when results exist
    current_results_df = df  # Store the results for exporting

def process_ips():
    if not stored_api_key:
        status_label.configure(text="❌ API Key is required! Please set it up first.", text_color="red")
        return

    api_key = load_api_key(password_entry.get().strip())
    if not api_key:
        status_label.configure(text="❌ Incorrect password or API Key not found!", text_color="red")
        return

    ip_text = ip_input.get("1.0", "end").strip()
    extracted_ips_list = extract_unique_public_ips(ip_text)

    # Display extracted IPs in the right panel
    ip_results.configure(state="normal")
    ip_results.delete("1.0", "end")
    
    if not extracted_ips_list:
        ip_results.insert("1.0", "⚠️ No valid public IPs found!")
        status_label.configure(text="⚠️ No valid public IPs found!", text_color="orange")
        ip_results.configure(state="disabled")
        return
    
    # Format IPs as "x.x.x.x","x.x.x.x"
    formatted_ips = ','.join([f'"{ip}"' for ip in extracted_ips_list])
    ip_results.insert("end", formatted_ips)
    ip_results.configure(state="disabled")
    
    # Join for API processing
    ip_list = extracted_ips_list

    results = [check_ip_reputation(api_key, ip) for ip in ip_list]
    df = pd.DataFrame(results)

    display_results(df)

# Function to save results as CSV
def save_results_csv():
    global current_results_df
    if current_results_df is None or current_results_df.empty:
        return
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Save Results As"
    )

    if file_path:
        current_results_df.to_csv(file_path, index=False)
        status_label.configure(text="✅ Results saved successfully!", text_color="green")
        
# Function to clear the results box
def clear_results():
    global current_results_df
    
    # Clear the IP results box
    ip_results.configure(state="normal")
    ip_results.delete("1.0", "end")
    ip_results.configure(state="disabled")
    
    # Clear the results box
    result_box.configure(state="normal")
    result_box.delete("1.0", "end")
    result_box.configure(state="disabled")
    
    # Disable the Save button
    save_csv_button.configure(state="disabled")
    
    # Clear the datafrome
    current_results_df = None
    

# Function to open GitHub repo
def open_github():
    webbrowser.open("https://github.com/str0mboli/IPRecon/")

# Create the GUI window
app = ctk.CTk()
app.geometry("1250x800")  
app.title("IP Recon - Bulk IP Reputation Checker")

# Load and display banner image at 500x80 px - UPDATED for PyInstaller
try:
    banner_image = ctk.CTkImage(Image.open(resource_path("IPReconBanner.png")), size=(422, 80))
    banner_label = ctk.CTkLabel(app, image=banner_image, text="")
    banner_label.pack(pady=(5, 2))
except Exception as e:
    print(f"Error loading banner image: {e}")

# Check if an API key is stored
stored_api_key = os.path.exists(API_KEY_FILE)

# API Key Section (Only shown if no key is stored)
api_key_label = ctk.CTkLabel(app, text="Enter AbuseIPDB API Key:")
api_key_label.pack(pady=(5, 2))

if not stored_api_key:
    password_label = ctk.CTkLabel(app, text="Create a Password:")
    password_label.pack(pady=(5, 2))
    password_entry = ctk.CTkEntry(app, show="*", width=900)
    password_entry.pack()

    api_key_label = ctk.CTkLabel(app, text="Enter AbuseIPDB API Key:")
    api_key_label.pack(pady=(5, 2))
    api_key_entry = ctk.CTkEntry(app, width=900)
    api_key_entry.pack()

    def store_password_and_api_key():
        password = password_entry.get().strip()
        api_key = api_key_entry.get().strip()

        if not password or not api_key:
            status_label.configure(text="❌ Password and API Key are required!", text_color="red")
            return

        # Save the API key
        save_api_key(api_key, password)

        # Inform the user and shut down the program
        status_label.configure(
            text="✅ Password and API Key stored! The program will shut down in 10 seconds. Please restart it to activate the API key.",
            text_color="green"
        )
        app.after(10000, app.destroy)  # Shut down the program after 10 seconds

    save_key_button = ctk.CTkButton(app, text="Save Password and API Key", command=store_password_and_api_key, width=250)
    save_key_button.pack(pady=(5, 2))
else:
    api_key_label.configure(text="Enter Password to Unlock API Key:")
    password_entry = ctk.CTkEntry(app, show="*", width=900)
    password_entry.pack()

    def unlock_api_key():
        password = password_entry.get().strip()
        api_key = load_api_key(password)

        if api_key:
            # Hide the password entry and unlock button
            password_entry.pack_forget()
            unlock_button.pack_forget()

            # Hide the "Enter Password to Unlock API Key" label
            api_key_label.pack_forget()

            # Update the status label to indicate success
            status_label.configure(text="✅ API Key unlocked! You can now run IP Recon.", text_color="green")
        else:
            # Display an error message if the password is incorrect
            status_label.configure(text="❌ Incorrect password or corrupted data!", text_color="red")

    unlock_button = ctk.CTkButton(app, text="Unlock", command=unlock_api_key, width=250)
    unlock_button.pack(pady=(5, 2))

# Create frame for top status bar
top_frame = ctk.CTkFrame(app, fg_color="transparent")
top_frame.pack(side="top", fill="x", pady=(5, 0))  # Add padding to separate it from the banner

# Status label at the top left
status_label = ctk.CTkLabel(top_frame, text="")
status_label.pack(side="left", padx=15)

# Create a frame to hold the input and results side by side
input_frame = ctk.CTkFrame(app, fg_color="transparent")
input_frame.pack(fill="both", expand=True, padx=10, pady=(5, 2))

# Left side: IP Input Section
left_frame = ctk.CTkFrame(input_frame)
left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

ip_input_label = ctk.CTkLabel(left_frame, text="Enter Text with IPs (use ctrl-v):")
ip_input_label.pack(pady=(5, 2))
ip_input = ctk.CTkTextbox(left_frame, height=200, width=440)
ip_input.pack(fill="both", expand=True, padx=10, pady=5)

# Right side: Extracted IPs
right_frame = ctk.CTkFrame(input_frame)
right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

ip_results_label = ctk.CTkLabel(right_frame, text="Extracted Public IPs:")
ip_results_label.pack(pady=(5, 2))
ip_results = ctk.CTkTextbox(right_frame, height=200, width=440, state="disabled")
ip_results.pack(fill="both", expand=True, padx=10, pady=5)

# Button frame
button_frame = ctk.CTkFrame(app, fg_color="transparent")
button_frame.pack(pady=(0, 5))

# Create a frame for center alignment of buttons
center_button_frame = ctk.CTkFrame(button_frame, fg_color="transparent")
center_button_frame.pack(pady=(2, 2))

# Add all buttons side by side
submit_button = ctk.CTkButton(center_button_frame, text="Run IP Recon", command=process_ips, width=150)
submit_button.pack(side="left", padx=(0, 10))

save_csv_button = ctk.CTkButton(center_button_frame, text="Save Results as CSV", command=save_results_csv, width=150, state="disabled")
save_csv_button.pack(side="left", padx=(0, 0))

clear_button = ctk.CTkButton(center_button_frame, text="Clear Results", command=clear_results, width=150)
clear_button.pack(side="left", padx=(10, 0))

# Results Frame
results_frame = ctk.CTkFrame(app)
results_frame.pack(fill="both", expand=True, padx=10, pady=(2, 2))

# Results Label and Box inside the frame
results_label = ctk.CTkLabel(results_frame, text="IP Recon Results Table")
results_label.pack(pady=(5, 2))

# Fixed Results Box inside the frame
result_box = ctk.CTkTextbox(results_frame, height=300, width=1230, wrap="none", font=("Courier New", 12))
result_box.pack(fill="both", expand=True, padx=10, pady=5)

# Create frame for bottom GitHub label
bottom_frame = ctk.CTkFrame(app, fg_color="transparent")
bottom_frame.pack(side="bottom", fill="x", pady=(0, 15))

# GitHub label stays at bottom right in the same frame
github_label = ctk.CTkLabel(bottom_frame, text="IP Recon v1.02 - GitHub Repository", text_color="white", cursor="hand2")
github_label.pack(side="right", padx=15)
github_label.bind("<Button-1>", lambda e: open_github())

app.mainloop()