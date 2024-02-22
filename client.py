import tkinter as tk
import nmap
from time import sleep
from socket import gethostname, socket, AF_INET, SOCK_DGRAM
from datetime import datetime
from json import load, dump
from requests import get
from platform import system as getarch
from flask import Flask
from threading import Thread

online_api = Flask(__name__)

SETTINGS_FILE = 'settings.json'
WIDTH, HEIGHT = 592, 454

class SeaHawks:
    def __init__(self, root, os, ipaddr):
        root.title(f"SeaHawks Harvester | {ipaddr} | {settings['version']}")
        root.geometry(f"{WIDTH}x{HEIGHT}+{(root.winfo_screenwidth() - WIDTH) // 2}+{(root.winfo_screenheight() - HEIGHT) // 2}")
        root.resizable(width=False, height=False)
        root.configure(background='#323232')
        root.iconbitmap('seahawks.ico')
        self.load_settings()

        self.create_label(root, gethostname(), x=30, y=30, width=200, height=30, os_size=os_size)
        self.create_label(root, f"Clients : {settings['clients']}", x=350, y=30, width=200, height=25, os_size=os_size, name='devices_label')
        self.create_label(root, f"Latence WAN : {int(get('https://cloudflare.com').elapsed.total_seconds() * 1000)}ms", x=350, y=70, width=200, height=25, os_size=os_size, name='wan_label')
        self.create_label(root, f"Dernier scan : {settings['lastscan']}", x=30, y=70, width=200, height=25, os_size=os_size, name='scan_label')

        self.scan_button = self.create_button(root, "Scan", self.scan_button_command, x=30, y=390, width=70, height=25, os_size=os_size)
        self.scan_listbox = self.create_listbox(root, x=30, y=140, width=518, height=220, os_size=os_size)

        self.wan_thread = Thread(target=self.update_wan_latency)
        self.wan_thread.daemon = True
        self.wan_thread.start()

        self.iprange_input = tk.StringVar()
        self.iprange_input.set('Plage IP (ex. 192.168.1.1-254): ')
        self.entry = tk.Entry(root, textvariable=self.iprange_input, font=('Arial', os_size), bg="#323232", fg="#ffffff", justify="left", bd=1, relief="solid")
        self.entry.place(x=30, y=105, width=518, height=30)

    def create_button(self, master, text, command, x, y, width, height, os_size):
        button = tk.Button(master, text=text, command=command, relief='solid', bg="#000000", borderwidth=1, font=('Arial', os_size), fg="#323232", justify="center")
        button.place(x=x, y=y, width=width, height=height)
        return button

    def create_label(self, master, text, x, y, width, height, os_size, name=None):
        label = tk.Label(master, text=text, relief='solid', bg="#323232", borderwidth=1, font=('Arial', os_size), fg="#ffffff", justify="left")
        label.place(x=x, y=y, width=width, height=height)

        if name:
            setattr(self, name, label)

    def create_listbox(self, master, x, y, width, height, os_size):
        self.scan_listbox = tk.Listbox(master, bg="#323232", borderwidth="1px", font=('Arial', os_size), fg="#ffffff", justify="left")
        self.scan_listbox.place(x=x, y=y, width=width, height=height)
        return self.scan_listbox
    
    def load_settings(self):
        with open(file=SETTINGS_FILE, mode='r', encoding='utf-8') as settings_file:
            self.settings = load(settings_file)

    def update_gui(self):
        self.scan_label.config(text=f"Dernier scan : {self.settings['lastscan']}")
        self.devices_label.config(text=f"Clients : {self.settings['clients']}")
    
    def scan_button_command(self):
        self.scan_button.config(state=tk.DISABLED)
        self.entry.config(state=tk.DISABLED)

        scan_thread = Thread(target=self.scan_range_update)
        scan_thread.start()
    
    def scan_range_update(self):
        ip_range = self.iprange_input.get().replace("Plage IP (ex. 192.168.1.1-254): ", "")
        self.iprange_input.set(f"Début du scan sur la plage {ip_range}")
        scan_results, total_hosts = scan_iprange(ip_range=ip_range)
        self.scan_listbox.delete(0, tk.END)

        for ip_address in scan_results:
            self.scan_listbox.insert(tk.END, f"[+] {ip_address} : {scan_results[ip_address]}")

        self.settings['clients'] = total_hosts
        self.settings['lastscan'] = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        with open(file=SETTINGS_FILE, mode='w', encoding='utf-8') as new_settings:
            dump(self.settings, new_settings, indent=4)

        self.load_settings()
        self.update_gui()

        self.scan_button.config(state=tk.NORMAL)
        self.entry.config(state=tk.NORMAL)
        self.iprange_input.set('Plage IP (ex. 192.168.1.1-254): ')

    def update_wan_latency(self):
        while True:
            wan_latency = int(get('https://cloudflare.com').elapsed.total_seconds() * 1000)
            self.wan_label.config(text=f"Latence WAN : {wan_latency}ms")
            
            sleep(1)

@online_api.route('/status', methods=['GET'])
def get_status():
    return 'online'

def run_flask_app():
    print('application started')
    online_api.run()

def get_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ipaddr = s.getsockname()[0]
    s.close()

    return ipaddr

def scan_iprange(ip_range: str):
    nmScan = nmap.PortScanner()
    nmScan.scan(hosts=ip_range, arguments='-T4 -A -v --top-ports 1000')

    ip_ports, total_hosts = {}, 0

    for host in nmScan.all_hosts():
        if nmScan[host].state() == 'up':
            total_hosts += 1
            ip_ports[host] = ''

            for proto in nmScan[host].all_protocols():
                lport = list(nmScan[host][proto].keys())
                lport.sort()

                for port in lport:
                    if nmScan[host][proto][port]['state'] == 'open':
                        ip_ports[host] += f"{port} "
    
    return ip_ports, total_hosts

if __name__ == "__main__":
    root = tk.Tk()

    with open(file=SETTINGS_FILE, mode='r', encoding='utf-8') as settings_file:
        settings = load(settings_file)

    os_size = 8 if getarch() == 'Windows' else 12
    ipaddr = get_ip()

    flask_thread = Thread(target=run_flask_app)
    flask_thread.start()

    app = SeaHawks(root, os=getarch(), ipaddr=ipaddr)
    root.mainloop()
