import customtkinter as ctk
import re
import ipaddress
import requests
import pandas as pd
import os
import webbrowser
from tabulate import tabulate
from tkinter import filedialog
from PIL import Image, ImageTk  # For handling the banner image

# CustomTkinter settings
ctk.set_appearance_mode("dark")  # Dark mode
ctk.set_default_color_theme("blue")  # Theme color

API_KEY_FILE = "api_key.txt"
current_results_df = None  # Store the current results for CSV export

# Function to save API key
def save_api_key(api_key):
    with open(API_KEY_FILE, "w") as f:
        f.write(api_key)

# Function to load API key if stored
def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    return None

def extract_unique_public_ips(text):
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}\b'

    ipv4_matches = re.findall(ipv4_pattern, text)
    ipv6_matches = re.findall(ipv6_pattern, text)
    all_ips = set(ipv4_matches + ipv6_matches)
    public_ips = sorted({ip for ip in all_ips if not ipaddress.ip_address(ip).is_private})

    return ",".join(public_ips) if public_ips else ""

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

    status_label.configure(text="✅ IP check complete! Select and copy results.", text_color="green")
    save_csv_button.configure(state="normal")  # Enable Save button when results exist
    current_results_df = df  # Store the results for exporting

def process_ips():
    api_key = load_api_key()
    if not api_key:
        status_label.configure(text="❌ API Key is required!", text_color="red")
        return

    ip_text = ip_input.get("1.0", "end").strip()
    extracted_ips = extract_unique_public_ips(ip_text)

    if not extracted_ips:
        status_label.configure(text="⚠️ No valid public IPs found!", text_color="orange")
        return

    ip_list = extracted_ips.split(",")

    results = [check_ip_reputation(api_key, ip) for ip in ip_list]
    df = pd.DataFrame(results)

    display_results(df)

def store_api_key():
    api_key = api_key_entry.get().strip()
    if api_key:
        save_api_key(api_key)
        api_key_entry.pack_forget()  # Hide API Key input field
        save_key_button.pack_forget()  # Hide the Save API Key button
        api_key_label.configure(text="✅ API Key stored successfully!", text_color="green")
        status_label.configure(text="API Key stored! You can now run IP Recon.", text_color="green")

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

# Function to open GitHub repo
def open_github():
    webbrowser.open("https://github.com/str0mboli/IPRecon/")

# Create the GUI window
app = ctk.CTk()
app.geometry("1250x800")  
app.title("IP Recon - Bulk IP Reputation Checker")

# Load and display banner image at 500x80 px
try:
    banner_image = ctk.CTkImage(Image.open("IPReconBanner.png"), size=(500, 80))
    banner_label = ctk.CTkLabel(app, image=banner_image, text="")
    banner_label.pack(pady=(5, 2))
except Exception as e:
    print(f"Error loading banner image: {e}")

# Check if an API key is stored
stored_api_key = load_api_key()

# API Key Section (Only shown if no key is stored)
api_key_label = ctk.CTkLabel(app, text="Enter AbuseIPDB API Key:")
api_key_label.pack(pady=(5, 2))

if not stored_api_key:
    api_key_entry = ctk.CTkEntry(app, width=900)
    api_key_entry.pack()
    save_key_button = ctk.CTkButton(app, text="Save API Key", command=store_api_key, width=250)
    save_key_button.pack(pady=(5, 2))
else:
    api_key_label.configure(text="✅ API Key Loaded", text_color="green")

# IP Input Section
ip_input_label = ctk.CTkLabel(app, text="Enter IPs (use ctrl-v):")
ip_input_label.pack(pady=(5, 2))
ip_input = ctk.CTkTextbox(app, height=200, width=900)
ip_input.pack()

submit_button = ctk.CTkButton(app, text="Run IP Recon", command=process_ips, width=250)
submit_button.pack(pady=(5, 2))

status_label = ctk.CTkLabel(app, text="")
status_label.pack(pady=(5, 2))

# Fixed Results Box
result_box = ctk.CTkTextbox(app, height=300, width=1230, wrap="none", font=("Courier New", 12))
result_box.pack(pady=(5, 2))

# Save Results as CSV Button
save_csv_button = ctk.CTkButton(app, text="Save Results as CSV", command=save_results_csv, width=250, state="disabled")
save_csv_button.pack(pady=(5, 2))

# GitHub Hyperlink at Bottom Right
github_label = ctk.CTkLabel(app, text="IP Recon v1.01 GitHub Repository", text_color="white", cursor="hand2")
github_label.pack(side="right", padx=15, pady=(0, 15), anchor="se")
github_label.bind("<Button-1>", lambda e: open_github())

app.mainloop()
