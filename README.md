# IP Recon
A Bulk IP Reputation Checker

This project is intended to provide a simple tool for security professionals to quickly check IP addresses for abuse.
The program will extract IPv4 and IPv6 addresses from text, remove duplicates and private IPs, and then send the results to AbuseIPDB.
The results are presented in simple table that you can copy suspect IPs from for deeper investigation.

Once the program runs, You will be prompted for an AbuseIPDB API key.
You can get an API key free at [AbuseIPDB.com](https://www.abuseipdb.com/)

After you enter your API key it will be saved within a .txt file. Going forward you will not need to reenter your API.


![image](https://github.com/user-attachments/assets/1ce4d521-3e2c-4c8d-a0d4-d0d05b5d8585)

![image](https://github.com/user-attachments/assets/465cd1b0-edf4-4a46-943e-c388260595e5)




File Hash: D5B9CCB4E375068AEB909C5175A17CF201BB8D4D9CCF42F81CF617EAE0409606 SHA256

---

**Installation Instructions**

Create a python environment

conda create -p ./env python=3.12 

---
**Dependancies**

pip install customtkinter requests pandas tabulate


Run: python ip_recon_gui.py

---

**To create a stand alone .exe**

pip install pyinstaller

pyinstaller --noconsole --onefile --name=IPRecon ip_recon_gui.py
