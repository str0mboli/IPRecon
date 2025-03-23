
# IP Recon

![IP Recon(Banner](https://github.com/user-attachments/assets/a9781156-3fdd-4ce5-a73c-94f936aa914d)


[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G61BDMMC)

Current Version: 1.02

A Bulk IP Reputation Checker

This project is intended to provide a simple tool for security professionals to quickly check IP addresses for abuse.
The program will extract IPv4 and IPv6 addresses from text, remove duplicates and private IPs, and then send the results to AbuseIPDB.
The results are presented in simple table that you can copy suspect IPs from for deeper investigation.

Once the program runs, You will be prompted for an AbuseIPDB API key.
You can get an API key free at [AbuseIPDB.com](https://www.abuseipdb.com/)

After you enter your API key it will be saved within a .txt file. Going forward you will not need to reenter your API.


![RPReconScreenShot](https://github.com/user-attachments/assets/a443b8ac-f2be-4345-95f5-3eca274d9f4b)


---

**Required Dependancies**

- customtkinter: GUI framework for modern UI
- pandas: Handles data processing & CSV export
- requests: Makes API requests to AbuseIPDB
- tabulate: Formats results into a table-like display
- pillow: Handles image (banner) loading
- cryptography: Allows encrypted API Key Storage

--

**Optional Dependancies**

- pyinstaller: allows the script to function as a standalone application

---

**Installation Instructions**

1: Clone the repository: git clone https://github.com/str0mboli/IPRecon.git
  - cd Path\to\IPRecon
    
2: Open ip_recon_gui.py in editor of choice (I use VS Code)

3: Create a python environment
  - conda create -p ./env python=3.12
    
4: Install dependencies     
  - pip install customtkinter requests pandas tabulate pillow cryptography
    
5: Run: python ip_recon_gui.py

---

**To create a stand alone .exe**

- pip install pyinstaller
  - pyinstaller --onefile --windowed --add-data "IPReconBanner.png;." --icon=IPReconIcon.ico --name "IP Recon" ip_recon_gui.py
