import requests
import matplotlib.pyplot as plt
from openpyxl.styles import Alignment
from matplotlib.widgets import Button
from matplotlib.patches import Rectangle
from datetime import datetime
import pandas as pd
import time
from matplotlib.gridspec import GridSpec
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import sys
import os
from contextlib import suppress
from PIL import Image, ImageTk
import subprocess
import os
import csv
import matplotlib.image as mpimg
import json
from pathlib import Path

if getattr(sys, 'frozen', False):
    with suppress(ModuleNotFoundError):
        import pyi_splash # shows error becasue pyi_splash is not yet loaded, still functional

#pyinstaller: python -m PyInstaller --noconsole --onedir --icon=images/croppedlogo.ico --splash=images/Loading.png --add-data "images;images" flowpro.py

# ---------- Globals ----------
running = False
start_time = None
settings = None
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
CACHE_FILE = Path(os.getenv('LOCALAPPDATA')) / "FlowPRO" / "last_ip.json"
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
IFM_MAC_PREFIX = "00:02:01"
PORT1_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[1]/iolinkdevice/pdin/getdata"}
PORT2_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[2]/iolinkdevice/pdin/getdata"}
PORT3_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[3]/iolinkdevice/pdin/getdata"}
PORT4_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[4]/iolinkdevice/pdin/getdata"}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------- Detecting IP ----------
def normalize_mac(mac: str):#
    return mac.replace(":", "").replace("-","").lower() if mac else None

# ---------- Decoders ----------
def decodeHighPressureIFM(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[2:-2]
    bar = (float(int(bin_value,2)))
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

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

def decodePressureKey(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[:16]
    psi = float(int(bin_value,2))
    bar = psi / 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

# ---------- Pyinstaller Pathing -----------
def resource_path(relative_path): # join os paths to base paths for accessing files
    if hasattr(sys, 'frozen'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def askForIP(session): # Unused, for direct IP connection support

    def saveIP(ip: str):
        data = {"last_ip":ip}
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f)

    def loadIP()-> str:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, "r") as f:
                data = json.load(f)
                return data.get("last_ip")
        return None

    s = session
    results = {}
    entry_font = ("Arial", 14)
    root = tk.Tk()
    root.attributes('-topmost', True)
    root.focus_force()
    root.title("FlowPRO")
    WINDOW_WIDTH = 500
    WINDOW_HEIGHT = 300
    root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    root.resizable(False, False)

    title_label = tk.Label(root, text="Direct Connect to Flow Skid", font=("Arial", 20, "bold"), fg="blue")
    title_label.pack(pady=10)

    main_frame = ttk.Frame(root, relief='solid')
    main_frame.pack(fill="both", expand=True,pady=10,padx=10)

    header = ttk.Label(main_frame, text="Please enter the IP displayed on the router inside the weatherproof box on your flow skid.",
                       font=("Arial",14), wraplength=400, justify='center')
    header.pack(expand=True, pady=10, padx=20)

    status_var = tk.StringVar(value="Enter an IP address to test connection")
    status_label = tk.Label(main_frame, textvariable=status_var, font=("Arial", 12),
                            relief="solid", padx=5, pady=5, justify="center",fg="blue")
    status_label.pack(padx=80, pady=10)

    ip = tk.Entry(main_frame, font=entry_font)
    ip.config(width=20)
    ip.config(selectborderwidth=3, width=20,justify='center')
    ip.pack(pady=10)
    ip.focus_set()
    cached_ip = loadIP()
    if cached_ip:
        ip.insert(0, cached_ip)

    def testIP(testip): # Unused
        url = f"http://{testip}/iolinkmaster"
        try:
            response = s.post(url, json=PORT1_PAYLOAD, timeout=2)
            return response.status_code == 200
        except:
            status_var.set("Connection failed, please retry")
            root.update()
            return False

    def submit(): # Unused
        current = ip.get()
        ip.delete(0, tk.END)
        ip.insert(0,"Working...")
        submit_button.config(state="disabled")
        testip = "".join(current.split())
        root.update()
        if testIP(testip):
            results['ip'] = testip
            saveIP(testip)
            root.destroy()
        else:
            submit_button.config(state="normal")
            ip.delete(0, tk.END)
            ip.insert(0,current)
            root.update()
    
    style = ttk.Style()
    style.configure("Big.TButton",font=("Arial",14,"bold"))
    submit_button = ttk.Button(main_frame, text="Submit", command=submit, style='Big.TButton')
    submit_button.pack(pady=10, ipadx=5, ipady=5)
    root.wait_window()
    return results

# ---------- Settings GUI -----------
def combinedWindow():  # Creates the combined settings/port overview screen
    global BASE_DIR, url

    # ------------------- Device Detection -------------------
    def findDevice(portNum): # id device by IoT deviceID
        deviceIDs = {
            2015: ["Keyence FD-H10 Flow Meter", "f","images/key_flow_img.jpg"],
            1463: ["SU8021 IFM Flow Meter", "f","images/ifm_flow_img.jpg"],
            452:  ["PN7692 IFM Pressure Sensor", "p","images/ifm_pressure_img.jpg"],
            1313: ["EIO344 IFM Moneo Blue|Classic Adapter", None,"images/ifm_moneo_img.jpg"],
            2016: ["Keyence FD-H20 Flow Meter", "f", "images/key_flow_img.jpg"],
            2008: ["Keyence GP-M400T Pressure Sensor", "p", "images/key_pressure_img.jpg"],
            450: ["PN7670 IFM Pressure Sensor", "p", "images/ifm_high_pressure_img.jpg"]
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
            print("UNCAUGHT ERROR")
            return

    MAX_IMAGE_SIZE = 135

    # ------------------- Port Frame Builder -------------------
    def createPortFrame(parent, title): # create a frame to display a titled port's info
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

        def resize_image(event=None): # resize port display image
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
    main_frame.grid_columnconfigure(1, weight=1)
    main_frame.grid_rowconfigure(0, weight=1)

    # ------------------- Left Panel (Settings) -------------------
    leftFrame = ttk.Frame(main_frame, relief="solid", padding=10)
    leftFrame.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)

    # ------------------- Right Panel (Ports) -------------------
    rightFrame = ttk.Frame(main_frame, relief="solid")
    rightFrame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

    # ------------------- FlowPRO Settings Widgets -------------------
    entry_font = ("Arial", 14)
    placeholder = "Auto Scale"
    results = {}

    def menuOpened(entry): # Auto Scale functionality
        if entry.get() == placeholder:
            entry.delete(0, tk.END)
            entry.config(fg="black")

    def menuClosed(entry):# Auto Scale functionality
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
    graph_format = ttk.Combobox(leftFrame, values=["Show all points","Show latest points"], font=entry_font)
    graph_format.current(0)
    graph_format.grid(row=2, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    graph_format.config(width=20)

    # Sample Interval
    sample_rate_values = ["0.5 Seconds","1 Second ","5 Seconds","10 Seconds","30 Seconds","60 Seconds"]
    sample_rate_var = tk.StringVar(value=sample_rate_values[3])

    def pick_sample_interval(): # create sample interval selection window
        popup = tk.Toplevel(root)
        popup.title("Select Sample Rate")
        popup.grab_set()
        frame = ttk.Frame(popup)
        frame.pack(padx=5, pady=10)
        listbox = tk.Listbox(frame, height=6, font=entry_font)
        scrollbar = ttk.Scrollbar(frame, command=listbox.yview)
        listbox.config(yscrollcommand=scrollbar.set)
        listbox.pack(side="left", fill="y")
        scrollbar.pack(side="right", fill="y")
        for v in sample_rate_values:
            listbox.insert("end", v)
        def choose(event=None):
            selection = listbox.get(listbox.curselection())
            sample_rate_var.set(selection)
            popup.destroy()
        listbox.bind("<<ListboxSelect>>", choose)

    ttk.Label(leftFrame, text="Sample Rate (s)").grid(row=3, column=0, pady=pady_val, sticky="w")
    ttk.Button(leftFrame, textvariable=sample_rate_var, command=pick_sample_interval, style='Big.TButton').grid(
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
        results['interval'] = sample_rate_var.get()[:-8]
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

    # ------------------- Info Icons (Simplified "i") -------------------
    info_texts = [
        "Select the pressure unit to display during the test. Supported pressure units are psi, bar, and kPa. NOTE: The selected unit in FlowPRO is independent of the displayed unit on the pressure sensor. Both readouts are displayed correctly in their respective units.",
        "Select the flow unit to display during the test. Supported flow units are L/min and GPM. NOTE: The selected unit in FlowPRO is independent of the displayed units on the flow meter. Both readouts are displayed correctly in their respective units.",
        "Select either “Show latest points” or “Show all points”. Showing the latest points will display the last 300 data points collected and scroll with incoming data (preferable for more granular data visibility). Show all points will display all collected data points and compress with incoming data (preferable for large scale data visibility).",
        "Select how often a sample is taken. Supported sample intervals are 0.5, 1, 5, 10, 30, and 60 seconds.",
        "Select the pressure minimum for the test (pressure y-axis minimum). Default value: 0. This value will scale automatically if incoming data exceeds the threshold. ",
        "Select the pressure maximum for the test (pressure y-axis maximum). Default value: 50. This value will scale automatically if incoming data exceeds the threshold. ",
        "Select the flow rate minimum for the test (flow rate y-axis minimum). Default value: 0. This value will scale automatically if incoming data exceeds the threshold. ",
        "Select the flow rate maximum for the test (flow rate y-axis maximum). Default value: 10. This value will scale automatically if incoming data exceeds the threshold. ",
        "Choose a test name. This test name will be the default file name for the saved Excel data file."
    ]

    info_frame = ttk.Frame(leftFrame)
    info_frame.grid(row=0, column=2, rowspan=10, sticky="n", padx=(5,0))

    icon_labels = []
    for i, text in enumerate(info_texts):
        lbl = tk.Label(info_frame, text="?", font=("Arial", 15, "bold"),
                       fg="blue", cursor="hand2")
        lbl.grid(row=i, column=0, pady=7, sticky="w")
        lbl.bind("<Button-1>", lambda e, t=text: tk.messagebox.showinfo("Info", t))
        icon_labels.append(lbl)

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
        if pf is None:
            return None
        pf.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")

    root.wait_window()
    return results
        

# ---------- Plotting ----------
def live_plot(x_unit="Time (s)"): # main method for sending, recieving, plotting, and saving the recorded data
    global running, current_interval, selected_interval, burst_mode, dual_flow
    global next_time, testnameheader, starttimeheader, pressureIDheader, flowIDheader, settings
    global port1, port2, port3, port4 # because ports are assigned in combinedWindow()

    ipiblue = "#5778A5"
    ipigold = "#F2B700"
    darkblue = "#003466"
    packerblue = "#0865CA"
    gray = "#EAEBED"
    ports = [port1, port2, port3, port4]
    flownum = 0
    for port in ports:
        if port is not None and port[1] == 'f':
            flownum+=1
    if flownum > 1:
        dual_flow = True

    plt.ion()
    
    if not settings:
        return
    if not settings.get('filename'):
        messagebox.showwarning("No Filename","Please retry and submit a file name.")
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

    def safe_number(n, default): # returns a default value if non-numeric
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

    starttime = datetime.now()

    # --- Create figure with GridSpec ---
    fig = plt.figure(figsize=(15,8))
    fig.canvas.manager.set_window_title(filename)
    manager = fig.canvas.manager
    window = getattr(manager, "window", None)
    if hasattr(window, "minsize"):
        window.minsize(1325, 600)
    gs = GridSpec(1, 2, width_ratios=[3, 1], wspace=0.3)

    # --- Main plot on left ---
    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = ax1.twinx()
    ax1.set_xlabel(x_unit, color=darkblue, fontsize = 20)
    ax1.set_ylabel("Pressure ("+str(p_unit)+")", color=darkblue, fontsize = 20)
    ax2.set_ylabel("Flow ("+str(f_unit)+")", color=darkblue, fontsize=20)
    ax1.set_title("FlowPRO Live Plot", fontsize = 20, color=darkblue, fontweight='bold')

    ax1.grid(True, which="both", linestyle="--",linewidth=0.4, alpha=0.5)

    line_p, = ax1.plot([], [], marker="o", color=packerblue, alpha=0.7)
    line_f, = ax2.plot([], [], marker="o", color=ipigold, alpha=0.7)
    if(dual_flow):
        line_f2, = ax2.plot([], [], marker="o", color=darkblue, alpha=0.7)
    ax1.set_ylim(p_min, p_max)
    ax2.set_ylim(f_min, f_max)

    # --- Readouts on right ---
    ax_readout = fig.add_subplot(gs[0, 1])
    ax_readout.axis("off")

    # --- Logo ---
    img = mpimg.imread(resource_path("images/logo.png"))
    newax = fig.add_axes([0, 0.82, 0.18, 0.18], anchor='NW')
    newax.imshow(img)
    newax.axis('off')

    # Add titles and text objects
    if dual_flow:
        ax_readout.text(0.13, 0.68, "High Flow", fontsize=18, ha='center', color=darkblue, fontweight='bold')
        flow_text = ax_readout.text(0.13, 0.58, "0.0"+str(settings.get('flow_unit')), fontsize=25, ha='center', color='black', bbox=dict(edgecolor=ipigold, facecolor='none', linewidth=2))
        ax_readout.text(0.13, 0.48, "Low Flow", fontsize=18, ha='center', color=darkblue, fontweight='bold')
        flow_text2 = ax_readout.text(0.13, 0.38, "0.0"+str(settings.get('flow_unit')), fontsize=25, ha='center', color='black', bbox=dict(edgecolor=darkblue, facecolor='none', linewidth=2))
        ax_readout.text(0.88, 0.58, "Pressure", fontsize=18, ha='center', color=darkblue, fontweight='bold')
        pressure_text = ax_readout.text(0.88, 0.48, "0.0"+str(settings.get('pressure_unit')), fontsize=25, ha='center', color='black', bbox=dict(edgecolor=ipiblue, facecolor='none', linewidth=2))
    else:
        ax_readout.text(0.13, 0.63, "Flow", fontsize=20, ha='center', color=darkblue, fontweight='bold')
        flow_text = ax_readout.text(0.13, 0.53, "0.0", fontsize=25, ha='center', color='black', fontweight='bold')
        ax_readout.text(0.13, 0.43, str(settings.get('flow_unit')), fontsize=25, ha='center', color=ipigold)

        ax_readout.text(0.88, 0.63, "Pressure", fontsize=20, ha='center', color=darkblue, fontweight='bold')
        pressure_text = ax_readout.text(0.88, 0.53, "0.0", fontsize=25, ha='center', color='black',fontweight='bold')
        ax_readout.text(0.88, 0.43, str(settings.get('pressure_unit')), fontsize=25, ha='center', color=packerblue)
        
    sample_rate_text = ax_readout.text(0.5, 0.2, "Sample Rate: "+str(current_interval)+"(s)", fontsize=20, fontweight='bold', ha='center', color='darkblue')
    status_text = ax_readout.text(0.5, 0.98, "Stopped", fontsize = 20, ha='center',color=darkblue, fontweight='bold')
    burst_text = ax_readout.text(0.5, 0.1, "Burst mode: Off", fontsize =15, ha='center',color='red', fontweight='bold')

    # --- Bounding Boxes ---
    ax_start_stop_box = plt.axes([0.675, 0.7, 0.28, 0.25])
    ax_start_stop_box.set_axis_off()
    start_stop_box = Rectangle(
        (0.05, 0.05), 0.9, 0.9, transform=ax_start_stop_box.transAxes, linewidth=2, edgecolor=darkblue,facecolor='none'
    )
    ax_start_stop_box.add_patch(start_stop_box)

    ax_readout_box = plt.axes([0.682, 0.34, 0.14, 0.37])
    ax_readout_box.set_axis_off()
    readout_box = Rectangle(
        (0.05, 0.05), 0.9, 0.9, transform=ax_readout_box.transAxes, linewidth=2, edgecolor=darkblue,facecolor='none'
    )
    ax_readout_box.add_patch(readout_box)

    ax_readout_box_2 = plt.axes([0.808, 0.34, 0.14, 0.37])
    ax_readout_box_2.set_axis_off()
    readout_box_2 = Rectangle(
        (0.05, 0.05), 0.9, 0.9, transform=ax_readout_box_2.transAxes, linewidth=2, edgecolor=darkblue,facecolor='none'
    )
    ax_readout_box_2.add_patch(readout_box_2)

    ax_burst_box = plt.axes([0.675, 0, 0.28, 0.35])
    ax_burst_box.set_axis_off()
    burst_box = Rectangle(
        (0.05, 0.05), 0.9, 0.9, transform=ax_burst_box.transAxes, linewidth=2, edgecolor=darkblue, facecolor='none'
    )
    ax_burst_box.add_patch(burst_box)

    # --- Buttons ---

    ax_start = plt.axes([0.71, 0.75, 0.1, 0.075])
    btn_start = Button(ax_start, "Start", color=ipiblue, hovercolor=darkblue)
    btn_start.label.set_color(gray)

    ax_stop  = plt.axes([0.82, 0.75, 0.1, 0.075])
    btn_stop  = Button(ax_stop, "Stop", color=ipiblue, hovercolor=darkblue)
    btn_stop.label.set_color(gray)

    ax_burst = plt.axes([0.765, 0.1, 0.1, 0.075])
    btn_burst = Button(ax_burst, "Burst", color=ipiblue, hovercolor=darkblue)
    btn_burst.label.set_color(gray)

    ax_burst_info = plt.axes([0.875, 0.11, 0.025, 0.05])
    btn_burst_info = Button(ax_burst_info, "?", color=ipiblue, hovercolor=darkblue)
    btn_burst_info.label.set_color(gray)

    for btn in (btn_burst, btn_start, btn_stop, btn_burst_info):
        btn.label.set_fontsize(16)
        btn.label.set_fontweight("bold")

    # --- Button click Events ---

    def start(event): # what to do on start click
        global running
        running = True
        global start_time
        if(start_time == None):
            start_time = time.time()
        status_text.set_text("Running")
        status_text.set_color('green')
        status_text.set_fontsize(20)
        plt.draw()

    def stop(event): # what to do on stop click
        global running
        running = False
        status_text.set_text("Stopped: Safe to Exit")
        status_text.set_fontsize(18)
        status_text.set_color('red')
        plt.draw()

    def toggleBurst(event): # what to do on burst click (toggles)
        global selected_interval
        global current_interval
        global burst_mode
        global next_time

        if not burst_mode:
            next_time = time.time()
            current_interval = 0.1
            burst_mode = True
            sample_rate_text.set_text("Sample Rate: Burst")
            burst_text.set_text("Burst mode: On")
            burst_text.set_color("green")
            plt.draw()
        else:
            current_interval = selected_interval
            burst_mode = False
            burst_text.set_text("Burst mode: Off")
            burst_text.set_color("red")
            sample_rate_text.set_text("Sample Rate: "+str(current_interval)+"(s)")
            plt.draw()

    def burstInfo(event): # display burst mode info
        global running
        if not running:
            messagebox.showinfo("Burst Mode Info", "This button will toggle burst mode on and off. Burst mode, when enabled, will lower the sample interval to 0.1 seconds. This allows the user to achieve higher granularity in critical stretches of the test. Burst mode can be toggled on and off while stopped or while testing.")

    btn_start.on_clicked(start)
    btn_stop.on_clicked(stop)
    btn_burst.on_clicked(toggleBurst)
    btn_burst_info.on_clicked(burstInfo)

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
            elif port[1] == 'f':
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

    #pressureIDheader = ["Pressure Sensor ID", "TEMP"] ######################################################
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
    if not file_path:
        messagebox.showerror("File path required", "Error: No designated file location, please retry")
        return
    
    csv_path = file_path.replace(".xlsx", "_temp.csv")

    with open(csv_path, "w", newline="") as file:
        csv.writer(file).writerow(header)

    payloads = [PORT1_PAYLOAD, PORT2_PAYLOAD, PORT3_PAYLOAD, PORT4_PAYLOAD]

    # --- Main loop ---
    x_data, p_data, f_data, f_data2 = [], [], [], []
    plt.show(block=False)
    while True:
        if not plt.fignum_exists(fig.number):
            break
        now = time.time()
        if running and now >= next_time:
            try:
                for slot, idx in live_ports.items():
                    response = session.post(url, json=payloads[idx])
                    response.raise_for_status()
                    resp_json = response.json()
                    raw_hex = resp_json.get("data", {}).get("value")
                    if slot == 'p':
                        if pressure_sensor == "PN7692 IFM Pressure Sensor":
                            p = decodePressureIFM(raw_hex)[p_unit_index]
                        elif pressure_sensor == "PN7670 IFM Pressure Sensor":
                            p = decodeHighPressureIFM(raw_hex)[p_unit_index]
                        else:
                            p = decodePressureKey(raw_hex)[p_unit_index]
                    if dual_flow:
                        if slot == 'f1':
                            f1 = decodeFlowKey(raw_hex)[f_unit_index]
                            if f1 < -1000 and len(f_data)>2: f1=f_data[-1]
                        elif slot == 'f2':
                            f2 = decodeFlowKey(raw_hex)[f_unit_index]
                            if f2 < -1000 and len(f_data2)>2: f2=f_data2[-1]
                    else:
                        print("Flow sensor 1: "+str(flow_sensor1))
                        if slot == 'f' and flow_sensor1 == "SU8021 IFM Flow Meter":
                            f = decodeFlowIFM(raw_hex)[f_unit_index]
                        elif slot == 'f':
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
                    flow_text.set_text(f"{f:.2f}")
                pressure_text.set_text(f"{p:.2f}")
                plt.draw()
            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")
        plt.pause(0.01)
    plt.ioff()

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


def testConnection(s):
        url = "http://192.168.50.10/iolinkmaster"
        try:
            response = s.post(url, json=PORT1_PAYLOAD, timeout=2)
            return response.status_code == 200
        except:
            return False
    
if __name__ == "__main__": # on application enter:
    try:
        if pyi_splash.is_alive():
            pyi_splash.close()
    except Exception as e:
        pass

    session = requests.Session() 
    url = "http://192.168.50.10/iolinkmaster"
    if testConnection(session):
        settings = combinedWindow()
        if settings:
            live_plot()
    else:
        messagebox.showerror("Error: Failed to Connect","Unable to locate IPI Flow Skid. Ensure you are connected to the provided router (IPI DFM).")