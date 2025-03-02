# IP Recon

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G61BDMMC)

Current Version: 1.01

A Bulk IP Reputation Checker

This project is intended to provide a simple tool for security professionals to quickly check IP addresses for abuse.
The program will extract IPv4 and IPv6 addresses from text, remove duplicates and private IPs, and then send the results to AbuseIPDB.
The results are presented in simple table that you can copy suspect IPs from for deeper investigation.

Once the program runs, You will be prompted for an AbuseIPDB API key.
You can get an API key free at [AbuseIPDB.com](https://www.abuseipdb.com/)

After you enter your API key it will be saved within a .txt file. Going forward you will not need to reenter your API.


![image](https://github.com/user-attachments/assets/3e8f6e83-0351-4033-a5e1-5750f344e271)


---

**Installation Instructions**

- Clone the repository: git clone https://github.com/str0mboli/IPRecon.git
  - cd Path\to\IPRecon
- Open ip_recon_gui.py in editor of choice (I use VS Code)
- Create a python environment
  - conda create -p ./env python=3.12
- Install dependencies     
  - pip install customtkinter requests pandas tabulate pillow
- Run: python ip_recon_gui.py

---

**To create a stand alone .exe**

- pip install pyinstaller
  - pyinstaller --noconsole --onefile --name=IPRecon ip_recon_gui.py
