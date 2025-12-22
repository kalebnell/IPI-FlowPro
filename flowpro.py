import requests
import threading
import ipaddress
import matplotlib.pyplot as plt
from openpyxl.styles import Alignment
from matplotlib.widgets import Button
from datetime import datetime
import pandas as pd
import time
from matplotlib.gridspec import GridSpec
import tkinter as tk
from tkinter import ttk, font, messagebox, filedialog
import sys
import os
from contextlib import suppress
import concurrent.futures
import subprocess
from PIL import Image, ImageTk
import os
import csv
from requests_toolbelt.adapters.source import SourceAddressAdapter

if getattr(sys, 'frozen', False):
    with suppress(ModuleNotFoundError):
        import pyi_splash

# reformat to exe with: pyinstaller --noconsole --onefile --icon="C:\Users\kbubn\OneDrive\Desktop\IPI\code\croppedlogo.ico" --splash="C:\Users\kbubn\OneDrive\Desktop\IPI\code\loading.png" C:\Users\kbubn\OneD
# rive\Desktop\IPI\code\flowpro.py

# ---------- Globals ----------
running = False
start_time = None
url = ""
current_interval = 10
selected_interval = None
burst_mode = False
next_time = None
port1 = None
port2 = None
port3 = None
port4 = None
dual_flow = False
TARGET_MAC_PREFIX = "00:02:01"
MAX_WORKERS = 50        # number of concurrent ping threads
BATCH_SIZE = 200        # how many IPs to schedule before checking ARP table
OVERALL_TIMEOUT = 20.0  # seconds to give up scanning the whole subnet
PING_TIMEOUT_MS = 700   # per-ping timeout in milliseconds (Windows uses ms)
PORT1_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[1]/iolinkdevice/pdin/getdata"}
PORT2_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[2]/iolinkdevice/pdin/getdata"}
PORT3_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[3]/iolinkdevice/pdin/getdata"}
PORT4_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[4]/iolinkdevice/pdin/getdata"}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUBNET = "192.168.1.0/24"

# ---------- Detecting IP ----------

def create_bound_session(source_ip):
    s = requests.session()
    s.mount("http://", SourceAddressAdapter(source_ip))
    s.mount("https://", SourceAddressAdapter(source_ip))
    return s

def get_active_subnets():
    output = subprocess.check_output("ipconfig", shell=True, text=True)
    results = []

    current_ip = None
    current_mask = None

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("IPv4 Address"):
            current_ip = line.split(":")[-1].strip()
        elif line.startswith("Subnet Mask"):
            current_mask = line.split(":")[-1].strip()
        if current_ip and current_mask:
            try:
                subnet = ipaddress.IPv4Network(
                    f"{current_ip}/{current_mask}", strict=False
                )
                results.append((str(subnet), current_ip))
            except:
                pass
            current_ip = None
            current_mask = None

    return results

def build_ip_list(subnet): # return a list of each ip to ping in the subnet
    net = ipaddress.ip_network(subnet, strict=False)
    return [str(h) for h in net.hosts()]


def ping_ip(ip, timeout_ms=PING_TIMEOUT_MS): # ping a given ip 
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def get_master_from_arp(prefix=TARGET_MAC_PREFIX): # check the arp list to see if master has been found
    try:
        arp_out = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None, None

    norm_prefix = prefix.lower().replace(":", "").replace("-", "")
    for line in arp_out.splitlines():
        cleaned = line.replace("-", "").replace(":", "").lower()
        if norm_prefix in cleaned:
            parts = line.split()
            if len(parts) >= 2:
                ip = None
                mac = None
                for token in parts:
                    if token.count(".") == 3 and ip is None:
                        ip = token.strip("()")
                    if (":" in token or "-" in token) and any(c.isalpha() for c in token):
                        mac = token
                if ip and mac:
                    return ip, mac
    return None, None


def threaded_find_master(subnet=SUBNET, max_workers=MAX_WORKERS, # main function for finding IFM master's ip.
                         batch_size=BATCH_SIZE, overall_timeout=OVERALL_TIMEOUT): # pings each known subnet's ips to add to arp list, then checks arp list for master
    
    ip_list = build_ip_list(subnet)
    total = len(ip_list)
    print(f"Scanning {total} addresses on {subnet} using up to {max_workers} workers...")

    start_time = time.time()
    found_event = threading.Event()
    found_result = {"ip": None, "mac": None}

    def ping_and_check(ip): # ping the passed ip and check if it matches required mac header.
        if found_event.is_set():
            return False
        ping_ip(ip)
        ip_found, mac_found = get_master_from_arp()
        if ip_found:
            found_result["ip"] = ip_found
            found_result["mac"] = mac_found
            found_event.set()
            return True
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe: # handling threading to ping ips quicker.
        futures = []
        for i, ip in enumerate(ip_list):
            if found_event.is_set(): # if the ip is found, exit the scan
                break
            if time.time() - start_time > overall_timeout: # if timeout is reached, terminate all threads and exit the scan
                break

            futures.append(exe.submit(ping_and_check, ip))

            if (i + 1) % batch_size == 0:
                time.sleep(0.2)
                ip_found, mac_found = get_master_from_arp()
                if ip_found:
                    found_result["ip"] = ip_found
                    found_result["mac"] = mac_found
                    found_event.set()
                    break

        try:
            timeout_left = max(0.0, overall_timeout - (time.time() - start_time))
            concurrent.futures.wait(futures, timeout=timeout_left)
        except Exception:
            pass
    try:
        if pyi_splash.is_alive():
            pyi_splash.close()
    except Exception as e:
        pass

    if found_result["ip"]: # if master is found, return its location so POST requests can be sent
        print("\nMATCH FOUND!")
        print(f"IP:  {found_result['ip']}")
        print(f"MAC: {found_result['mac']}")
        return found_result["ip"]
    else:
        print("\n----- Unable to find any IFM Masters! -----")
        return None
    
def threaded_find_master_all_interfaces():
    subnets = get_active_subnets()
    print("Detected subnets:", subnets)

    for subnet, local_ip in subnets:
        print(f"Scanning {subnet} ...")
        ip = threaded_find_master(subnet=subnet)
        if ip:
            return ip, local_ip

    return None, None

# ---------- Decoders ----------

def decodePressureIFM(raw_hex): # decode raw hex data from IFM pressure sensor PN-7692
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[2:-2]
    bar = (float(int(bin_value,2)))/10
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

def decodeFlowKey(raw_hex): # decode raw hex data from Keyence flow meter FD-H20 Ultrasonic Flow Meter
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[:32]
    inst_flow = float(int(bin_value,2))
    L_min = inst_flow/100
    if(L_min > 100):
        L_min -= 42949672.96
    G_min = L_min*0.264172
    return [L_min, G_min]

def decodeFlowIFM(raw_hex): # decode raw hex data from IFM flow meter 
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[32:64]
    inst_flow = float(int(bin_value,2))
    L_min = inst_flow/60
    G_min = L_min * 0.2641720524
    return [L_min, G_min]

# ---------- Pyinstaller Pathing -----------
def resource_path(relative_path):
    if hasattr(sys, 'frozen'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ---------- Settings GUI -----------
def combinedWindow():
    global BASE_DIR, url

    # ------------------- Device Detection -------------------
    def findDevice(portNum):
        deviceIDs = {
            2015: ["Keyence FD-H10 Flow Meter", "f","images/key_flow_img.jpg"],
            1463: ["SU8021 IFM Flow Meter", "f","images/ifm_flow_img.jpg"],
            452:  ["PN7692 IFM Pressure Sensor", "p","images/ifm_pressure_img.jpg"],
            1313: ["EIO344 IFM Moneo Blue|Classic Adapter", None,"images/ifm_moneo_img.jpg"],
            2016: ["Keyence FD-H20 Flow Meter", "f", "images/key_flow_img.jpg"]
        }
        try:
            payload = {"code":"request","cid":-1,
                       "adr":f"/iolinkmaster/port[{portNum}]/iolinkdevice/deviceid/getdata"}
            portrequest = session.post(url, json=payload, verify=False)
            portrequest.raise_for_status()
            json_data = portrequest.json()
            id_val = json_data.get("data", {}).get("value")
            return deviceIDs.get(id_val)
        except Exception as e:
            print(f"Port {portNum} detection failed: {e}")
            return None

    MAX_IMAGE_SIZE = 135

    # ------------------- Port Frame Builder -------------------
    def createPortFrame(parent, title):
        global port1, port2, port3, port4

        frame = ttk.Frame(parent, padding=10, relief="ridge")
        frame.grid_propagate(False)

        header = ttk.Label(frame, text=title, font=("Arial", 14, "bold"))
        header.grid(row=0, column=0, sticky="n", pady=(0,5))

        picture = tk.Canvas(frame, bg="white", width=MAX_IMAGE_SIZE, height=MAX_IMAGE_SIZE)
        picture.grid(row=1, column=0, sticky="n", pady=5)

        desc = ttk.Label(frame, text=None, font=("Arial", 10), anchor="center", justify="center", wraplength=150)
        desc.grid(row=2, column=0, sticky="n", pady=5)

        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        portNum = int(title[-1:])
        device = findDevice(portNum)
        if portNum == 1:
            port1 = device
        elif portNum == 2:
            port2 = device
        elif portNum == 3:
            port3 = device
        elif portNum == 4:
            port4 = device
        img_file = device[2] if device else "images/empty.jpg"

        def resize_image(event=None):
            try:
                img = Image.open(resource_path(img_file))
                img = img.resize((MAX_IMAGE_SIZE, MAX_IMAGE_SIZE))
                photo = ImageTk.PhotoImage(img)
                picture.image = photo
                picture.delete("all")
                picture.create_image(0, 0, anchor="nw", image=photo)
            except Exception as e:
                print(f"Error loading image: {e}")

        picture.bind("<Configure>", resize_image)
        desc.config(text=device[0] if device else "None")

        return frame

    # ------------------- Main Window -------------------
    root = tk.Tk()
    root.lift()
    root.attributes('-topmost', True)
    root.after(300, lambda: root.attributes('-topmost', False))
    root.focus_force()
    root.title("FlowPRO Settings + Port Overview")
    WINDOW_WIDTH = 800
    WINDOW_HEIGHT = 580
    root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    root.resizable(False, False)

    # Title
    title_label = tk.Label(root, text="FlowPRO Settings & Port Overview",
                            font=("Arial", 20, "bold"), fg="blue")
    title_label.pack(pady=10)

    # Main container
    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True)
    main_frame.grid_columnconfigure(0, weight=0)  # Left column 50%
    main_frame.grid_columnconfigure(1, weight=1)  # Right column 50%
    main_frame.grid_rowconfigure(0, weight=1)


    # ------------------- Left Panel (Settings) -------------------
    leftFrame = ttk.Frame(main_frame,relief="solid", padding=10)
    leftFrame.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)

    # ------------------- Right Panel (Ports) -------------------
    rightFrame = ttk.Frame(main_frame, relief="solid")
    rightFrame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

    # ------------------- FlowPRO Settings Widgets -------------------
    entry_font = ("Arial", 14)
    placeholder = "Auto Scale"
    results = {}

    def menuOpened(entry):
        if entry.get() == placeholder:
            entry.delete(0, tk.END)
            entry.config(fg="black")

    def menuClosed(entry):
        if entry.get() == "":
            entry.insert(0, placeholder)
            entry.config(fg="grey")

    pady_val = 5
    ipady_val = 3

    buttonStyle = ttk.Style()
    buttonStyle.configure('Big.TButton', font=('Arial',15))

    # Comboboxes
    ttk.Label(leftFrame, text="Pressure Unit").grid(row=0, column=0, pady=pady_val, sticky="w")
    pressure_unit = ttk.Combobox(leftFrame, values=["psi","bar","kpa"], font=entry_font)
    pressure_unit.current(0)
    pressure_unit.grid(row=0, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    pressure_unit.config(width=20)

    ttk.Label(leftFrame, text="Flow Unit").grid(row=1, column=0, pady=pady_val, sticky="w")
    flow_unit = ttk.Combobox(leftFrame, values=["l/m","g/m"], font=entry_font)
    flow_unit.current(0)
    flow_unit.grid(row=1, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    flow_unit.config(width=20)

    ttk.Label(leftFrame, text="Graph Format").grid(row=2, column=0, pady=pady_val, sticky="w")
    graph_format = ttk.Combobox(leftFrame, values=["Show latest points","Show all points"], font=entry_font)
    graph_format.current(0)
    graph_format.grid(row=2, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    graph_format.config(width=20)

    # Sample Interval
    interval_values = ["0.5 Seconds","1 Second ","5 Seconds","10 Seconds","30 Seconds","60 Seconds"]
    interval_var = tk.StringVar(value=interval_values[3])

    def pick_sample_interval():
        popup = tk.Toplevel(root)
        popup.title("Select Sample Interval")
        popup.grab_set()
        frame = ttk.Frame(popup)
        frame.pack(padx=5, pady=10)
        listbox = tk.Listbox(frame, height=6, font=entry_font)
        scrollbar = ttk.Scrollbar(frame, command=listbox.yview)
        listbox.config(yscrollcommand=scrollbar.set)
        listbox.pack(side="left", fill="y")
        scrollbar.pack(side="right", fill="y")
        for v in interval_values:
            listbox.insert("end", v)
        def choose(event=None):
            selection = listbox.get(listbox.curselection())
            interval_var.set(selection)
            popup.destroy()
        listbox.bind("<<ListboxSelect>>", choose)

    ttk.Label(leftFrame, text="Sample Interval (s)").grid(row=3, column=0, pady=pady_val, sticky="w")
    ttk.Button(leftFrame, textvariable=interval_var, command=pick_sample_interval, style='Big.TButton').grid(
        row=3, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)

    # Numeric fields
    fields = ["Pressure Min","Pressure Max","Flow Min","Flow Max"]
    entries = []
    for i, name in enumerate(fields, start=4):
        ttk.Label(leftFrame, text=name).grid(row=i, column=0, sticky="w", pady=pady_val)
        entry = tk.Entry(leftFrame, font=entry_font)
        entry.insert(0, placeholder)
        entry.bind("<FocusIn>", lambda e, ent=entry: menuOpened(ent))
        entry.bind("<FocusOut>", lambda e, ent=entry: menuClosed(ent))
        entry.grid(row=i, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
        entry.config(width=20)
        entries.append(entry)

    pressure_min, pressure_max, flow_min, flow_max = entries

    # Test name
    ttk.Label(leftFrame, text="Test Name").grid(row=8, column=0, sticky="w", pady=pady_val)
    filename = tk.Entry(leftFrame, font=entry_font)
    filename.grid(row=8, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    filename.config(width=20)

    # Submit button
    def submit():
        results['pressure_unit'] = pressure_unit.get()
        results['flow_unit'] = flow_unit.get()
        results['graph_format'] = graph_format.get()
        results['pressure_min'] = pressure_min.get() if pressure_min.get() != placeholder else None
        results['pressure_max'] = pressure_max.get() if pressure_max.get() != placeholder else None
        results['flow_min'] = flow_min.get() if flow_min.get() != placeholder else None
        results['flow_max'] = flow_max.get() if flow_max.get() != placeholder else None
        results['filename'] = filename.get()
        results['interval'] = interval_var.get()[:-8]
        root.destroy()

    ttk.Button(leftFrame, text="Submit", command=submit, style='Big.TButton').grid(row=9, column=1, pady=10)
    
    picture = tk.Canvas(leftFrame, bg="white", width=90, height=90)
    picture.grid(row=9, column=0, sticky="sw", pady=10)
    try:
        img = Image.open(resource_path("images/logo.png"))
        img = img.resize((90,90))
        photo = ImageTk.PhotoImage(img)
        picture.image = photo
        picture.delete("all")
        picture.create_image(0, 0, anchor="nw", image=photo)
    except Exception as e:
        print(f"Error loading image: {e}")

    # ------------------- Port Overview -------------------
    for r in range(2):
        rightFrame.grid_rowconfigure(r, weight=1)
    for c in range(2):
        rightFrame.grid_columnconfigure(c, weight=1)

    titles = ["Port 1","Port 2","Port 3","Port 4"]
    for i, t in enumerate(titles):
        r = i // 2
        c = i % 2
        pf = createPortFrame(rightFrame, t)
        pf.grid(row=r, column=c, padx=10, pady=10, sticky="nsew", )  # tight 2x2 grid

    root.mainloop()
    return results
        

# ---------- Plotting ----------
def live_plot(x_unit="Time (s)"): # main method for sending, recieving, plotting, and saving the recorded data
    global running, current_interval, selected_interval, burst_mode, dual_flow
    global next_time, testnameheader, starttimeheader, pressureIDheader, flowIDheader

    settings = combinedWindow()

    global port1, port2, port3, port4 # because ports are assigned in combinedWindow()

    ports = [port1, port2, port3, port4]
    flownum = 0
    for port in ports:
        if port is not None and port[1] == 'f':
            flownum+=1
    if flownum > 1:
        dual_flow = True

    plt.ion()
    
    if len(settings) == 0:
        messagebox.showwarning("No Filename","Please retry and submit a filename.")
        return
    
    p_unit = settings.get('pressure_unit')
    f_unit = settings.get('flow_unit')
    sliding = settings.get('graph_format') == "Show latest points"

    p_unit_index = 1
    f_unit_index = 0
    if(settings.get('pressure_unit') == 'bar'):
        p_unit_index = 0
        p_unit = "bar"
    elif(settings.get('pressure_unit') == 'kpa'):
        p_unit_index = 2
        p_unit = "kpa"
    if(settings.get('flow_unit') == 'g/m'):
        f_unit_index = 1
        f_unit = "g/m"

    def safe_number(n, default):
        try:
            return float(n)
        except:
            return default
        
    p_min = safe_number(settings.get('pressure_min'), 0)
    p_max = safe_number(settings.get('pressure_max'), 50)
    f_min = safe_number(settings.get('flow_min'), 0)
    f_max = safe_number(settings.get('flow_max'), 10)

    selected_interval = safe_number(settings.get('interval'), 10)
    current_interval = selected_interval

    filename = str(settings.get('filename'))

    root = tk.Tk()
    root.withdraw()

    starttime = datetime.now()

    # --- Create figure with GridSpec ---
    fig = plt.figure(figsize=(15,8))
    fig.canvas.manager.set_window_title(filename)
    gs = GridSpec(1, 2, width_ratios=[3, 1], wspace=0.3)

    # --- Main plot on left ---
    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = ax1.twinx()
    ax1.set_xlabel(x_unit)
    ax1.set_ylabel("Pressure ("+str(p_unit)+")", color="tab:blue", fontsize = 20)
    ax2.set_ylabel("Flow ("+str(f_unit)+")", color="tab:orange", fontsize=20)
    ax1.set_title("Live Plot of Readings", fontsize = 20)

    ax1.grid(True, which="both", linestyle="--",linewidth=0.4, alpha=0.5)

    line_p, = ax1.plot([], [], marker="o", color="tab:blue", alpha=0.7)
    line_f, = ax2.plot([], [], marker="o", color="tab:orange", alpha=0.7)
    if(dual_flow):
        line_f2, = ax2.plot([], [], marker="o", color="tab:green", alpha=0.7)
    ax1.set_ylim(p_min, p_max)
    ax2.set_ylim(f_min, f_max)

    # --- Readouts on right ---
    ax_readout = fig.add_subplot(gs[0, 1])
    ax_readout.axis("off")

    # Add titles and text objects
    if dual_flow:
        ax_readout.text(0.5, 0.75, "High Flow (FD-H20)", fontsize=15, ha='center')
        flow_text = ax_readout.text(0.5, 0.67, "0.0", fontsize=25, ha='center', color='orange')
        ax_readout.text(0.5, 0.55, "Low Flow (FD-H10)", fontsize=15, ha='center')
        flow_text2 = ax_readout.text(0.5, 0.47, "0.0", fontsize=25, ha='center', color='green')
        ax_readout.text(0.5, 0.35, "Current Pressure", fontsize=15, ha='center')
        pressure_text = ax_readout.text(0.5, 0.27, "0.0", fontsize=25, ha='center', color='blue')
    else:
        ax_readout.text(0.5, 0.65, "Current Flow", fontsize=15, ha='center')
        flow_text = ax_readout.text(0.5, 0.55, "0.0", fontsize=25, ha='center', color='orange')
        ax_readout.text(0.5, 0.43, "Current Pressure", fontsize=15, ha='center')
        pressure_text = ax_readout.text(0.5, 0.33, "0.0", fontsize=25, ha='center', color='blue')
    status_text = ax_readout.text(0.5, 0.97, "Stopped", fontsize = 25, ha='center',color='red', fontweight='bold')
    burst_text = ax_readout.text(0.5, 0.125, "Burst mode: Off", fontsize =15, ha='center',color='red')

    # --- Buttons ---

    ax_start = plt.axes([0.71, 0.75, 0.1, 0.075])
    ax_stop  = plt.axes([0.82, 0.75, 0.1, 0.075])
    btn_start = Button(ax_start, "Start")
    btn_stop  = Button(ax_stop, "Stop")
    ax_burst = plt.axes([0.765, 0.1, 0.1, 0.075])
    btn_burst = Button(ax_burst, "Burst")

    for btn in (btn_burst, btn_start, btn_stop):
        btn.label.set_fontsize(16)
        btn.label.set_fontweight("bold")

    def start(event):
        global running
        running = True
        global start_time
        if(start_time == None):
            start_time = time.time()
        status_text.set_text("Running")
        status_text.set_color("green")
        status_text.set_fontsize(20)
        plt.draw()

    def stop(event):
        global running
        running = False
        status_text.set_text("Stopped: Safe to Exit")
        status_text.set_fontsize(15)
        status_text.set_color("red")
        plt.draw()

    def toggleBurst(event):
        global selected_interval
        global current_interval
        global burst_mode
        global next_time

        if not burst_mode:
            next_time = time.time()
            current_interval = 0.1
            burst_mode = True
            burst_text.set_text("Burst mode: On")
            burst_text.set_color("green")
            plt.draw()
        else:
            current_interval = selected_interval
            burst_mode = False
            burst_text.set_text("Burst mode: Off")
            burst_text.set_color("red")
            plt.draw()

    btn_start.on_clicked(start)
    btn_stop.on_clicked(stop)
    btn_burst.on_clicked(toggleBurst)

    next_time = time.time()
    first_sample = True

    if(dual_flow):
        header = ["Time Stamp", "Elapsed Time (s)", "Pressure ("+p_unit+")","High Flow ("+f_unit+")","Low Flow ("+f_unit+")"]
    else:
        header = ["Time Stamp", "Elapsed Time (s)", "Pressure ("+p_unit+")","Flow Rate ("+f_unit+")"]

    testnameheader = ["Test Name", filename]
    starttimeheader = ["Test Start", starttime]

    flow_sensor1 = None
    live_ports = {}
    for i, port in enumerate(ports):
        if port is not None:
            if port[1] == 'p':
                pressure_sensor = port[0]
                live_ports['p'] = i
            elif port[0] == "Keyence FD-H10 Flow Meter" or port[0] =="Keyence FD-H20 Flow Meter":
                if dual_flow:
                    if port[0] == "Keyence FD-H20 Flow Meter":
                        flow_sensor1 = port[0]
                        live_ports['f1'] = i
                    else:
                        flow_sensor2 = port[0]
                        live_ports['f2'] = i
                else:
                    flow_sensor1 = port[0]
                    live_ports['f'] = i

    #pressureIDheader = ["Pressure Sensor ID", "TEMP"] ########################################################################
    try:
        pressureIDheader = ["Pressure Sensor ID", pressure_sensor]
        if dual_flow:
            flowIDheader1 = ["High Flow ID", flow_sensor1]
            flowIDheader2 = ["Low Flow ID", flow_sensor2]
        else:
            flowIDheader = ["Flow Meter ID", flow_sensor1]
    except UnboundLocalError:
        messagebox.showerror("Error","Please ensure that all sensors are properly connected.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension = ".xlsx",
        filetypes = [("Excel Files", "*.xlsx"), ("All Files","*.*")],
        initialfile = filename,
        title = "Save Excel File As..."
    )
    root.destroy()
    if not file_path:
        messagebox.showerror("Error: No designated file location, please retry", "File path required")
        return
    
    csv_path = file_path.replace(".xlsx", "_temp.csv")

    with open(csv_path, "w", newline="") as file:
        csv.writer(file).writerow(header)

    payloads = [PORT1_PAYLOAD, PORT2_PAYLOAD, PORT3_PAYLOAD, PORT4_PAYLOAD]

    # --- Main loop ---
    x_data, p_data, f_data, f_data2 = [], [], [], []
    while plt.fignum_exists(fig.number):
        now = time.time()
        if running and now >= next_time:
            try:
                for slot, idx in live_ports.items():
                    response = session.post(url, json=payloads[idx])
                    response.raise_for_status()
                    resp_json = response.json()
                    raw_hex = resp_json.get("data", {}).get("value")
                    if slot == 'p':
                        p = decodePressureIFM(raw_hex)[p_unit_index]
                    if dual_flow:
                        if slot == 'f1':
                            f1 = decodeFlowKey(raw_hex)[f_unit_index]
                            if f1 < -1000 and len(f_data)>2: f1=f_data[-1]
                        elif slot == 'f2':
                            f2 = decodeFlowKey(raw_hex)[f_unit_index]
                            if f2 < -1000 and len(f_data2)>2: f2=f_data2[-1]
                    else:
                        if slot == 'f':
                            f = decodeFlowKey(raw_hex)[f_unit_index]
                            if f < -1000 and len(f_data)>2: f=f_data[-1]
                #p=0#########################
                t = datetime.now()
                if first_sample:
                    et = 0.0
                    start_time = now
                    next_time = start_time + current_interval
                    first_sample = False
                else:
                    et = round(time.time() - start_time, 2)
                    next_time += current_interval
                try:
                    with open(csv_path, "a", newline="") as file:
                        writer = csv.writer(file)
                        if dual_flow:
                            writer.writerow([t, et, p, f1, f2])
                        else:
                            writer.writerow([t, et, p, f])
                except UnboundLocalError:
                    messagebox.showerror("Error","Please ensure that all sensors are properly connected.")
                    return
                
                x_data.append(et)
                p_data.append(p)
                if dual_flow:
                    f_data.append(f1)
                    f_data2.append(f2)
                else:
                    f_data.append(f)
                if dual_flow:
                    if f1 > f_max:
                        f_max = f1+5
                        ax2.set_ylim(f_min, f_max)
                    if f2 > f_max:
                        f_max = f2+5
                        ax2.set_ylim(f_min, f_max)
                    if f1 < f_min:
                        f_min = f1-5
                        ax2.set_ylim(f_min, f_max)
                    if f2 < f_min:
                        f_min = f2-5
                        ax2.set_ylim(f_min, f_max)
                else:
                    if f > f_max:
                        f_max = f+5
                        ax2.set_ylim(f_min, f_max)
                    if f < f_min:
                        f_min = f-5
                        ax2.set_ylim(f_min, f_max)
                if p > p_max:
                    p_max = p+5
                    ax1.set_ylim(p_min, p_max)
                # --- Keep sliding window ---
                if(sliding):
                    window_size = 300
                    if len(x_data) > window_size:
                        x_data = x_data[-window_size:]
                        p_data = p_data[-window_size:]
                        if dual_flow:
                            f_data = f_data[-window_size:]
                            f_data2 = f_data2[-window_size:]
                        else:
                            f_data = f_data[-window_size:]
                # --- Update plots ---
                line_p.set_xdata(x_data)
                line_p.set_ydata(p_data)
                line_f.set_xdata(x_data)
                line_f.set_ydata(f_data)
                if dual_flow:
                    line_f2.set_xdata(x_data)
                    line_f2.set_ydata(f_data2)
                ax1.set_xlim(min(x_data), max(x_data))
                # --- Update readouts ---
                if dual_flow:
                    flow_text.set_text(f"{f1:.2f}"+f_unit)
                    flow_text2.set_text(f"{f2:.2f}"+f_unit)
                else:
                    flow_text.set_text(f"{f:.2f}"+f_unit)
                pressure_text.set_text(f"{p:.2f}"+p_unit)
                plt.draw()
            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")
        plt.pause(0.01)
    plt.ioff()
    plt.show()

    df = pd.read_csv(csv_path)
    with pd.ExcelWriter(file_path, engine="openpyxl") as writer:
        pd.DataFrame(columns=testnameheader).to_excel(writer, index=False, startrow=0)
        pd.DataFrame(columns=starttimeheader).to_excel(writer, index=False, startrow=1)
        pd.DataFrame(columns=pressureIDheader).to_excel(writer, index=False, startrow=2)

        row = 3
        if dual_flow:
            pd.DataFrame(columns=flowIDheader1).to_excel(writer, index=False, startrow=row); row+=1
            pd.DataFrame(columns=flowIDheader2).to_excel(writer, index=False, startrow=row); row+=1
        else:
            pd.DataFrame(columns=flowIDheader).to_excel(writer, index=False, startrow=row); row+=1

        df.to_excel(writer, index=False, startrow=row)
        worksheet = writer.sheets['Sheet1']
        for column_cells in worksheet.columns:
            max_length = 0
            column_letter = column_cells[0].column_letter
            for cell in column_cells:
                try:
                    cell.alignment = Alignment(horizontal='left', vertical='center')
                    max_length = max(max_length, len(str(cell.value)))
                except:
                    pass
            worksheet.column_dimensions[column_letter].width = max_length
    os.remove(csv_path)
    messagebox.showinfo("File Saved", f"File saved to:\n{file_path}")

    
if __name__ == "__main__": # on application enter: 
    master_ip, local_ip = threaded_find_master_all_interfaces()
    if master_ip:
        session = create_bound_session(local_ip)
        url = f"http://{master_ip}/iolinkmaster"
        live_plot()
    else:
        session = None
        messagebox.showerror("Error: Failed to Connect", "Unable to locate IP Flow Skid. Ensure you are connected to the provided router (IPI DFM)")