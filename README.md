
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



<div align="center">
  <h2>Choose Your Encryption Method</h2>
</div>

**FERNET API ENCRYPTION** - Standard Edition: ip_recon_gui.py

After you enter your API key, it is saved as an ecrypted file using AES and fernet technologies. You wont have to enter your API again.
As an added bonus, the encrypted file uses your device as the key. Even if the API file was stolen it is useless unless ran on the machine that created it.

-https://cryptography.io/en/latest/fernet/

--

**NON-STORED PASSWORD BASED AES ENCRYPTION** - Non-Fernet Edition: ip_recon_gui_NF.py

When you runt he program for the first time you will be prompted for a password and your API key. This stores your API as an encrypted file. Your password is not stored, it is hashed and used as the encryption key. 

IP Recon will need to restart in order to finalize the encryption process. It will shut down after 10 seconds or the user can close the application and restart it. Once initial setup is complete you can unlock IP Recon with your password. Since passwords are not stored in the app there is no way to reset your password.

Should you lose or forget your password, you will need to delete the api.key.encrypted file. Restart the program and enter a new word along with your API key.

---


![image](https://github.com/user-attachments/assets/ba421360-4278-4a33-be0e-82487fa3ea2f)


![image](https://github.com/user-attachments/assets/41bd3b8a-1102-404f-92c1-6787ae489329)

---



---

**Required Dependancies**

- customtkinter: GUI framework for modern UI
- pandas: Handles data processing & CSV export
- requests: Makes API requests to AbuseIPDB
- tabulate: Formats results into a table-like display
- pillow: Handles image (banner) loading
- cryptography: Allows encrypted API Key Storage

**RP Recon NF Edition Dependencies**

- pycryptodome: Allows encrpyted API storage (replaces cryptography)

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

  - For the NF edition run: pip install customtkinter requests pandas tabulate pillow pycryptodome
    
5: Run the application 
  - python ip_recon_gui.py

   or
   
  - Run: python ip_recon_gui_NF.py

---

**To create a stand alone .exe**

1. pip install pyinstaller
  - pyinstaller --onefile --windowed --add-data "IPReconBanner.png;." --icon=IPReconIcon.ico --name "IP Recon" ip_recon_gui.py

or

  - pyinstaller --onefile --windowed --add-data "IPReconBanner.png;." --icon=IPReconIcon.ico --name "IP Recon" ip_recon_gui_NF.py 
