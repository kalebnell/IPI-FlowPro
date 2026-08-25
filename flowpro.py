import requests
import matplotlib.pyplot as plt
from matplotlib.widgets import Button, TextBox
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
import csv
import matplotlib.image as mpimg
import json
from pathlib import Path

if getattr(sys, 'frozen', False):
    with suppress(ModuleNotFoundError):
        import pyi_splash # type: ignore : shows error becasue pyi_splash is not yet loaded, still functional

#pyinstaller: python -m PyInstaller  --onedir --noconsole --icon=images/croppedlogo.ico --splash=images/Loading.png --add-data "images;images" flowpro.py

# -*- coding: utf-8 -*-

# ---------- Globals ----------
running = False
start_time = None
settings = None
url = "http://192.168.50.10/iolinkmaster"
selected_interval = None
burst_mode = False
next_time = None
port1 = None
port2 = None
port3 = None
port4 = None
port5 = None
port6 = None
port7 = None
port8 = None
dual_flow = False
dual_pressure = False
eight_port = False
CACHE_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
CACHE_FILE = CACHE_DIR / "last_test_settings.json"
PORT1_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[1]/iolinkdevice/pdin/getdata"}
PORT2_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[2]/iolinkdevice/pdin/getdata"}
PORT3_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[3]/iolinkdevice/pdin/getdata"}
PORT4_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[4]/iolinkdevice/pdin/getdata"}
PORT5_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[5]/iolinkdevice/pdin/getdata"}
PORT6_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[6]/iolinkdevice/pdin/getdata"}
PORT7_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[7]/iolinkdevice/pdin/getdata"}
PORT8_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[8]/iolinkdevice/pdin/getdata"}
VERSION_NUMBER = "1.1.4"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def safe_number(n, default): # returns a default value if non-numeric
    try:
        return float(n), True
    except:
        return default, False

# ---------- Decoders ----------
def decodeTC(raw_hex):
    data = bytes.fromhex(raw_hex)
    temps = []
    for i in range(0, len(data), 2):
        raw = int.from_bytes(data[i:i+2], byteorder="big", signed=True)
        if raw == -32766:
            temps.append(None) # Wire Break
        else:
            temp_c = raw / 10.0
            temp_f = temp_c * 9/5 + 32
            temps.append((temp_c, temp_f))

    return temps

def decode8060(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[0:16]
    bar = (float(int(bin_value, 2))) / 10
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]
    
def decode7602(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[0:16]
    bar = (float(int(bin_value, 2))) / 100
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

def decodeHighPressureIFM(raw_hex): # decode raw hex data from IFM high pressure sensor (PN7670)
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[2:-2]
    bar = (float(int(bin_value,2)))
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

def decodeStatusBIFM(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[:16]
    decimal = (float(int(bin_value,2)))
    psi = 0.145 * decimal
    bar = 0.0689476 * psi
    Kpa = 6.89476 * psi
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
    if L_min > 300:
        L_min -=71582786.52
    G_min = L_min * 0.2641720524
    return [L_min, G_min]

def decodePressureKey(raw_hex): # decode raw hex data from Keyence pressure transducer
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[:16]
    psi = float(int(bin_value,2))
    bar = psi / 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

def decodePressure2293(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[:-2]
    psi = 0.14504 * float(int(bin_value, 2))
    if psi > 400:
        psi -= 2376.19032
    bar = 0.0689476 * psi
    Kpa = bar *100
    return [bar, psi, Kpa]

def decodePressure2293B(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[:16]
    psi = 0.0145038 * float(int(bin_value, 2))
    if psi > 400:
        psi -= 950.3759988
    bar = 0.0689476 * psi
    Kpa = bar *100
    return [bar, psi, Kpa]

def decode_4_20_mA_Pressure(raw_hex, start_val, end_val):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[:16]
    decimal = (float(int(bin_value,2)))
    mA = decimal - 4000
    psi_per_mA = (((float(end_val) - float(start_val)) / 16) / 1000)
    psi = mA * psi_per_mA
    bar = 0.0689476 * psi
    Kpa = 6.89476 * psi
    return [bar, psi, Kpa]

def decodePressure_1402(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[:32]
    bar = (float(int(bin_value,2))) / 1000
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

def decodeFDH32_flow(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[:32]
    inst_flow = float(int(bin_value,2))
    L_min = inst_flow/100
    if(L_min > 9999):
        L_min -= 42949672.96
    G_min = L_min*0.264172
    return [L_min, G_min]

def decodeKeller23SXio(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[0:32]
    val = (float(int(bin_value,2)))
    if val > 1000000:
        val -= 4294967295
    Kpa = val / 1000
    bar = Kpa/100
    psi = bar * 14.5038
    return [bar, psi, Kpa]


# ---------- Pyinstaller Pathing -----------
def resource_path(relative_path): # join os paths to base paths for accessing files
    if hasattr(sys, 'frozen'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ---------- Settings GUI -----------
def combinedWindow():  # Creates the combined settings/port overview screen
    global BASE_DIR, url

    # ------------------- Device Detection -------------------
    def findDevice(portNum): # id device by IoT deviceID
        deviceIDs = {
            2015: ["Keyence FD-H10 Flow Meter", "f","images/key_flow_img.jpg"],
            2017: ["Keyence FD-H32 Flow Meter", "f", "images/key_flow_img.jpg"],
            1463: ["SU8021 IFM Flow Meter", "f","images/ifm_flow_img.jpg"],
            452:  ["PN7692/PN7292 IFM Pressure Sensor", "p","images/ifm_pressure_img.jpg"],
            1313: ["EIO344 IFM Moneo Blue|Classic Adapter", None,"images/ifm_moneo_img.jpg"],
            2016: ["Keyence FD-H20 Flow Meter", "f", "images/key_flow_img.jpg"],
            2008: ["Keyence GPM400-T", "p", "images/key_pressure_img.jpg"],
            450: ["PN7670 IFM Pressure Sensor", "p", "images/ifm_high_pressure_img.jpg"],
            610: ["DP4200 IFM 4-20mA Converter", "p", "images/DP4200.jpg"],
            1871: ["PG1402 IFM Pressure Sensor", "p", "images/ifm_1402_pressure.png"],
            629: ["PN7292/PN7692 Status B IFM Pressure Sensor", "p","images/ifm_pressure_img.jpg"],
            472: ["PN2293 IFM Pressure Sensor", "p", "images/ifm_pressure_img.jpg"],
            988: ["PN2293 Status B IFM Pressure Sensor", "p", "images/ifm_pressure_img.jpg"],
            69131: ["AXL E IOL TC4/K M12 Thermocouple Converter", "t", "images/thermocouple_converter.jpg"],
            1216: ["PV8060 IFM Pressure Sensor", "p", "images/8060.jpg"],
            853: ["PV7602 IFM Pressure Sensor", "p", "images/8060.jpg"],
            1067940: ["PA-23SXio Keller Pressure Sensor", "p", "images/keller.jpg"]
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
            return

    MAX_IMAGE_SIZE = 135

    # ------------------- Port Frame Builder -------------------
    def createPortFrame(parent, title): # create a frame to display a titled port's info
        global port1, port2, port3, port4, port5, port6, port7, port8, VERSION_NUMBER

        frame = ttk.Frame(parent, padding=10, relief="ridge")
        frame.grid_propagate(False)
        frame.config(width=200, height=260)

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
        match portNum:
            case 1:
                port1 = device
            case 2:
                port2 = device
            case 3:
                port3 = device
            case 4:
                port4 = device
            case 5:
                port5 = device
            case 6: 
                port6 = device
            case 7:
                port7 = device
            case 8:
                port8 = device

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
    root.title(f"FlowPRO™ Settings + Port Overview (Version {VERSION_NUMBER})")
    WINDOW_HEIGHT = 620
    if not eight_port:
        WINDOW_WIDTH = 800
    else:
        WINDOW_WIDTH = 1100
    root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    root.resizable(False, False)

    # Title
    title_label = tk.Label(root, text="FlowPRO™ Settings & Port Overview",
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
    pressure_unit = ttk.Combobox(leftFrame, values=["psi","bar","kpa"], font=entry_font, state="readonly")
    pressure_unit.current(0)
    pressure_unit.grid(row=0, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    pressure_unit.config(width=20)

    ttk.Label(leftFrame, text="Flow Unit").grid(row=1, column=0, pady=pady_val, sticky="w")
    flow_unit = ttk.Combobox(leftFrame, values=["l/m","g/m"], font=entry_font, state="readonly")
    flow_unit.current(0)
    flow_unit.grid(row=1, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    flow_unit.config(width=20)

    ttk.Label(leftFrame, text="Graph Format").grid(row=2, column=0, pady=pady_val, sticky="w")
    graph_format = ttk.Combobox(leftFrame, values=["Show all points","Show latest points"], font=entry_font, state="readonly")
    graph_format.current(0)
    graph_format.grid(row=2, column=1, pady=pady_val, sticky="ew", ipady=ipady_val)
    graph_format.config(width=20)

    # Sample Rate
    sample_rate_values = ["0.5 Seconds","1 Second","5 Seconds","10 Seconds","30 Seconds","60 Seconds"]
    sample_rate_var = tk.StringVar(value=sample_rate_values[3])
    sample_rate_to_value = {"0.5 Seconds": "0.5","1 Second":"1","5 Seconds":"5","10 Seconds":"10","30 Seconds":"30","60 Seconds":"60", "60":"60 Seconds", "30":"30 Seconds", "10":"10 Seconds","5":"5 Seconds","1":"1 Second","0.5":"0.5 Seconds"}

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
    for i, name in enumerate(fields, start=4): # Enable the Auto Scale automatically populating in the max/min fields
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
        results['interval'] = sample_rate_to_value[sample_rate_var.get()]
        save_settings(results)
        root.destroy()

    ttk.Button(leftFrame, text="Submit", command=submit, style='Big.TButton').grid(row=10, column=1, pady=5)

    def recall_settings():
        nonlocal pressure_unit, flow_unit, graph_format, pressure_min, pressure_max, flow_min, flow_max, filename, sample_rate_var
        settings_dict = load_last_settings()
        if settings_dict == {}:
            return
        pressure_unit.set(settings_dict['pressure_unit'])
        flow_unit.set(settings_dict['flow_unit'])
        graph_format.set(settings_dict['graph_format'])
        pressure_min.delete(0, tk.END)
        pressure_min.insert(0, settings_dict['pressure_min']) if settings_dict['pressure_min'] != None else pressure_min.insert(0, placeholder)
        pressure_max.delete(0, tk.END)
        pressure_max.insert(0, settings_dict['pressure_max']) if settings_dict['pressure_max'] != None else pressure_max.insert(0, placeholder)
        flow_min.delete(0, tk.END)
        flow_min.insert(0, settings_dict['flow_min']) if settings_dict['flow_min'] != None else flow_min.insert(0, placeholder)
        flow_max.delete(0, tk.END)
        flow_max.insert(0, settings_dict['flow_max']) if settings_dict['flow_max'] != None else flow_max.insert(0, placeholder)
        filename.delete(0, tk.END)
        filename.insert(0, settings_dict['filename'])
        sample_rate_var.set(sample_rate_to_value[settings_dict['interval']])
    
    ttk.Button(leftFrame, text="Load Last Settings", command = recall_settings, style = 'Big.TButton').grid(row=9, column=1, pady=5)

    picture = tk.Canvas(leftFrame, bg="white", width=90, height=90)
    picture.grid(row=10, column=0, sticky="sw", pady=10)
    try:
        img = Image.open(resource_path("images/logo.png"))
        img = img.resize((90,90))
        photo = ImageTk.PhotoImage(img)
        picture.image = photo
        picture.delete("all")
        picture.create_image(0, 0, anchor="nw", image=photo)
    except Exception as e:
        print(f"Error loading image: {e}")

    # ------------------- Info Icons -------------------
    info_texts = [
        "Select the pressure unit to display during the test. Supported pressure units are psi, bar, and kPa. NOTE: The selected unit in FlowPRO™ is independent of the displayed unit on the pressure sensor. Both readouts are displayed correctly in their respective units.",
        "Select the flow unit to display during the test. Supported flow units are L/min and GPM. NOTE: The selected unit in FlowPRO™ is independent of the displayed units on the flow meter. Both readouts are displayed correctly in their respective units.",
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
    rows=2
    if eight_port:
        cols=4
    else:
        cols=2
    for r in range(rows):
        rightFrame.grid_rowconfigure(r, weight=1)
    for c in range(cols):
        rightFrame.grid_columnconfigure(c, weight=1)
    four_port_titles = ["Port 1", "Port 2", "Port 3", "Port 4"]
    eight_port_titles = ["Port 1", "Port 2", "Port 3", "Port 4", "Port 5", "Port 6", "Port 7", "Port 8"]
    if eight_port:
        titles = eight_port_titles
    else:
        titles = four_port_titles
    for i, t in enumerate(titles):
        r = i //cols
        c = i % cols
        pf = createPortFrame(rightFrame, t)
        if pf is None:
            return None
        pf.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")

    root.wait_window()
    return results
        

# ---------- Plotting ----------
def live_plot(x_unit="Time (s)"): # main method for sending, recieving, plotting, and saving the recorded data
    global running, current_interval, selected_interval, burst_mode, dual_flow, dual_pressure
    global next_time, testnameheader, starttimeheader, pressureIDheader, flowIDheader, settings
    global port1, port2, port3, port4, port5, port6, port7, port8

    running, burst_mode, dual_flow, dual_pressure = False, False, False, False
    start_time, next_time = None, None

    if not settings: # settings window was exited
        return 
    if not settings.get('filename'): # no filename entered
        messagebox.showwarning("No Filename","Please retry and submit a file name.")
        return

    ipiblue = "#5778A5"
    ipigold = "#F2B700"
    darkblue = "#003466"
    packerblue = "#0865CA"
    gray = "#EAEBED"

    manual_p_ylim = False
    manual_f_ylim = False

    four_port_ports = [port1, port2, port3, port4]
    eight_port_ports = [port1, port2, port3, port4, port5, port6, port7, port8]
    flownum = 0
    if eight_port:
        ports = eight_port_ports
    else:
        ports = four_port_ports
    for port in ports:
        if port is not None and port[1] == 'f':
            flownum+=1
        if port is not None and port[0] == "DP4200 IFM 4-20mA Converter":
            dual_pressure = True
    if flownum > 1:
        dual_flow = True

    plt.ion()
    
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
        
    p_min, p_min_entered = safe_number(settings.get('pressure_min'), 0)
    p_max, p_max_entered = safe_number(settings.get('pressure_max'), 50)
    f_min, f_min_entered = safe_number(settings.get('flow_min'), 0)
    f_max, f_max_entered = safe_number(settings.get('flow_max'), 10)

    selected_interval, _ = safe_number(settings.get('interval'), 10)
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
    ax1.set_title("FlowPRO™ Live Plot", fontsize = 20, color=darkblue, fontweight='bold')

    ax1.grid(True, which="both", linestyle="--",linewidth=0.4, alpha=0.5)

    line_p, = ax1.plot([], [], marker="o", color=packerblue, alpha=0.7)
    line_f, = ax2.plot([], [], marker="o", color=ipigold, alpha=0.7)
    if dual_pressure:
        line_dhp, = ax1.plot([], [], marker="o", color = darkblue, alpha=0.7)
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
        pressure_text = ax_readout.text(0.88, 0.48, "0.0"+str(settings.get('pressure_unit')), fontsize=25, ha='center', color='black', bbox=dict(edgecolor=packerblue, facecolor='none', linewidth=2))
    elif dual_pressure:
        ax_readout.text(0.13, 0.43, "Downhole\nPressure", fontsize=18, ha='center', color='black', fontweight='bold')
        dhp_text = ax_readout.text(0.13, 0.36, "0.0"+ str(settings.get('pressure_unit')), fontsize=20, ha='center', color=darkblue, fontweight='bold')
        ax_readout.text(0.13, 0.64, "Surface\nPressure", fontsize=18, ha='center', color='black', fontweight='bold')
        pressure_text = ax_readout.text(0.13, 0.57, "0.0"+str(settings.get('pressure_unit')), fontsize=20, ha='center', color=packerblue, fontweight='bold')
        ax_readout.text(0.88, 0.58, "Flow", fontsize=18, ha='center', color='black', fontweight='bold')
        flow_text = ax_readout.text(0.88, 0.48, "0.0"+str(settings.get('flow_unit')), fontsize=20, ha='center', color=ipigold, fontweight='bold')
    else:
        ax_readout.text(0.13, 0.63, "Flow", fontsize=20, ha='center', color=darkblue, fontweight='bold')
        flow_text = ax_readout.text(0.13, 0.53, "0.0", fontsize=25, ha='center', color='black', fontweight='bold')
        ax_readout.text(0.13, 0.43, str(settings.get('flow_unit')), fontsize=25, ha='center', color=ipigold)

        ax_readout.text(0.88, 0.63, "Pressure", fontsize=20, ha='center', color=darkblue, fontweight='bold')
        pressure_text = ax_readout.text(0.88, 0.53, "0.0", fontsize=25, ha='center', color='black',fontweight='bold')
        ax_readout.text(0.88, 0.43, str(settings.get('pressure_unit')), fontsize=25, ha='center', color=packerblue)
        
    sample_rate_text = ax_readout.text(0.5, 0.2, "Sample Rate: "+str(current_interval)+"(s)", fontsize=20, fontweight='bold', ha='center', color=darkblue)
    status_text = ax_readout.text(0.5, 0.98, "Stopped", fontsize = 20, ha='center',color=darkblue, fontweight='bold')
    burst_text = ax_readout.text(0.5, 0.1, "Burst mode: Off", fontsize =15, ha='center',color='red', fontweight='bold')
    ax_readout.text(0.5, 1.1, time.strftime("%m/%d/%Y"), fontsize=15, ha='center', fontweight='bold')

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

    if dual_pressure:
        ax_dual_pressure_box = plt.axes([0.682, 0.348, 0.14, 0.185])
        ax_dual_pressure_box.set_axis_off()
        dual_pressure_box = Rectangle(
            (0.05, 0.05), 0.9, 0.9, transform=ax_dual_pressure_box.transAxes, linewidth=2, edgecolor=darkblue, facecolor='none'
        )
        ax_dual_pressure_box.add_patch(dual_pressure_box)

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

    tb_pmin = plt.axes([0.12, 0.02, 0.04, 0.04])
    tb_pmax = plt.axes([0.24, 0.02, 0.04, 0.04])
    tb_fmin = plt.axes([0.5, 0.02, 0.04, 0.04])
    tb_fmax = plt.axes([0.62, 0.02, 0.04, 0.04])

    pmin_box = TextBox(tb_pmin, "P Min:", initial=str(p_min), textalignment='center', label_pad=0.1)
    pmin_box.label.set_fontsize(12)
    pmin_box.label.set_fontweight('bold')
    pmin_box.label.set_color(darkblue)
    pmax_box = TextBox(tb_pmax, "P Max:", initial=str(p_max), textalignment='center', label_pad=0.1)
    pmax_box.label.set_fontsize(12)
    pmax_box.label.set_fontweight('bold')
    pmax_box.label.set_color(darkblue)
    fmin_box = TextBox(tb_fmin, "F Min:", initial=str(f_min), textalignment='center', label_pad=0.1)
    fmin_box.label.set_fontsize(12)
    fmin_box.label.set_fontweight('bold')
    fmin_box.label.set_color(darkblue)
    fmax_box = TextBox(tb_fmax, "F Max:", initial=str(f_max), textalignment='center', label_pad=0.1)
    fmax_box.label.set_fontsize(12)
    fmax_box.label.set_fontweight('bold')
    fmax_box.label.set_color(darkblue)

    # --- Button click Events ---
    def update_pmin(text):
        nonlocal p_min, manual_p_ylim
        with suppress(ValueError):
            p_min = float(text)
            manual_p_ylim = True
            ax1.set_ylim(p_min, p_max)
            fig.canvas.draw_idle()

    def update_pmax(text):
        nonlocal p_max, manual_p_ylim
        with suppress(ValueError):
            p_max = float(text)
            manual_p_ylim = True        
            ax1.set_ylim(p_min, p_max)
            fig.canvas.draw_idle()

    def update_fmin(text):
        nonlocal f_min, manual_f_ylim
        with suppress(ValueError):
            f_min = float(text)
            manual_f_ylim = True
            ax2.set_ylim(f_min, f_max)
            fig.canvas.draw_idle()

    def update_fmax(text):
        nonlocal f_min, manual_f_ylim
        with suppress(ValueError):
            f_max = float(text)
            manual_f_ylim = True
            ax2.set_ylim(f_min, f_max)
            fig.canvas.draw_idle()

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
    pmin_box.on_submit(update_pmin)
    pmax_box.on_submit(update_pmax)
    fmin_box.on_submit(update_fmin)
    fmax_box.on_submit(update_fmax)

    next_time = time.time()
    first_sample = True

    if dual_pressure and not dual_flow:
        header = ["Time Stamp", "Elapsed Time (s)", "Surface Pressure ("+p_unit+")", "Downhole Pressure ("+p_unit+")", "Flow Rate ("+f_unit+")"]
    elif(dual_flow and not dual_pressure):
        header = ["Time Stamp", "Elapsed Time (s)", "Pressure ("+p_unit+")","High Flow ("+f_unit+")","Low Flow ("+f_unit+")"]
    else:
        header = ["Time Stamp", "Elapsed Time (s)", "Pressure ("+p_unit+")","Flow Rate ("+f_unit+")"]

    testnameheader = ["Test Name", filename]
    starttimeheader = ["Test Start", starttime]

    class TwoValueDialog(simpledialog.Dialog):
        def body(self, master):
            self.geometry("420x130")
            tk.Label(master, text="Downhole Pressure Minimum: ", font=("Arial", 14, 'bold')).grid(row=0, column=0)
            tk.Label(master, text="Downhole Pressure Maximum: ", font=("Arial", 14, 'bold')).grid(row=1, column=0)

            self.e1 = tk.Entry(master)
            self.e2 = tk.Entry(master)

            self.e1.grid(row=0, column=1)
            self.e2.grid(row=1, column=1)
            return self.e1
        
        def apply(self):
            self.result = (self.e1.get(), self.e2.get())

    flow_sensor1 = None
    live_ports = {}
    for i, port in enumerate(ports):
        if port is not None:
            if port[0] == "DP4200 IFM 4-20mA Converter":
                downhole_sensor = port[0] 
                live_ports['dp4200'] = i
            elif port[1] == 'p':
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

    try:
        pressureIDheader = ["Pressure Sensor ID", pressure_sensor]
        if dual_pressure:
            downholeIDheader = ["Downhole Pressure ID", downhole_sensor]
        if dual_flow:
            flowIDheader1 = ["High Flow ID", flow_sensor1]
            flowIDheader2 = ["Low Flow ID", flow_sensor2]
        else:
            flowIDheader = ["Flow Meter ID", flow_sensor1]
    except UnboundLocalError:
        messagebox.showerror("Error","Please ensure that all sensors are properly connected.")
        plt.close(fig)
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension = ".xlsx",
        filetypes = [("Excel Files", "*.xlsx"), ("All Files","*.*")],
        initialfile = filename,
        title = "Save Excel File As..."
    )
    if not file_path:
        messagebox.showerror("File path required", "Error: No designated file location, please retry")
        plt.close(fig)
        return
    
    csv_path = file_path.replace(".xlsx", "_temp.csv")

    with open(csv_path, "w", newline="") as file:
        csv.writer(file).writerow(header)

    if dual_pressure:
        leave = False
        root = tk.Tk()
        root.withdraw()
        
        while True:
            dialog = TwoValueDialog(root, "Please Enter Downhole Pressure Bounds")
            if dialog.result is None:
                leave = messagebox.askokcancel(
                    "Quit FlowPRO™", 
                    "This action will close FlowPRO, are you sure you want to continue?" 
                )
                if leave:
                    break
                continue
                
            raw_val1, raw_val2 = dialog.result
            
            start_val, valid1 = safe_number(raw_val1, 0)
            end_val, valid2 = safe_number(raw_val2, 0)
            
            if valid1 and valid2:
                break
            else:
                messagebox.showwarning("Enter Valid Pressure Bounds", "The pressure bounds you entered were not valid, please retry.")
        if leave:
            plt.close('all')
            return
        
    payloads = [PORT1_PAYLOAD, PORT2_PAYLOAD, PORT3_PAYLOAD, PORT4_PAYLOAD, PORT5_PAYLOAD, PORT6_PAYLOAD, PORT7_PAYLOAD, PORT8_PAYLOAD]

    # --- Main loop ---
    x_data, p_data, f_data, f_data2, dhp_data = [], [], [], [], []
    plt.show(block=False)
    while True:
        if not plt.fignum_exists(fig.number):
            plt.close("all")
            break
        now = time.time()
        if running and now >= next_time:
            try:
                for slot, idx in live_ports.items():
                    response = session.post(url, json=payloads[idx])
                    response.raise_for_status()
                    resp_json = response.json()
                    raw_hex = resp_json.get("data", {}).get("value")
                    try:
                        if slot == 'p':
                            if pressure_sensor == "PN7692/PN7292 IFM Pressure Sensor" or pressure_sensor == "PN7292 IFM Pressure Sensor":
                                p = decodePressureIFM(raw_hex)[p_unit_index]
                            elif pressure_sensor == "PN7292/PN7692 Status B IFM Pressure Sensor":
                                p = decodeStatusBIFM(raw_hex)[p_unit_index]
                            elif pressure_sensor == "PN7670 IFM Pressure Sensor":
                                p = decodeHighPressureIFM(raw_hex)[p_unit_index]
                            elif pressure_sensor == "PG1402 IFM Pressure Sensor":
                                p = decodePressure_1402(raw_hex)[p_unit_index]
                            elif pressure_sensor == "PN2293/PN2693 Status B IFM Pressure Sensor":
                                p = decodePressure2293B(raw_hex)[p_unit_index]
                            elif pressure_sensor == "PN2293/PN2693 IFM Pressure Sensor":
                                p = decodePressure2293(raw_hex)[p_unit_index]
                            else:
                                p = decodePressureKey(raw_hex)[p_unit_index]
                        elif slot == 'dp4200':
                            downhole_pressure = decode_4_20_mA_Pressure(raw_hex, start_val, end_val)[p_unit_index]
                        if dual_flow:
                            if slot == 'f1':
                                f1 = decodeFlowKey(raw_hex)[f_unit_index]
                                if f1 < -1000 and len(f_data)>2: f1=f_data[-1]
                            elif slot == 'f2':
                                f2 = decodeFlowKey(raw_hex)[f_unit_index]
                                if f2 < -1000 and len(f_data2)>2: f2=f_data2[-1]
                        else:
                            if slot == 'f' and flow_sensor1 == "SU8021 IFM Flow Meter":
                                f = decodeFlowIFM(raw_hex)[f_unit_index]
                            elif slot =='f' and flow_sensor1 == "Keyence FD-H32 Flow Meter":
                                f = decodeFDH32_flow(raw_hex)[f_unit_index]
                            elif slot == 'f':
                                f = decodeFlowKey(raw_hex)[f_unit_index]
                                if f < -1000 and len(f_data)>2: f=f_data[-1]
                    except TypeError as e:
                        messagebox.showerror("Error: Sensor Disconnected", "Program has been shut down - please reconnect sensor and restart.")
                        plt.close(fig)
                        return

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
                        elif dual_pressure:
                            writer.writerow([t, et, p, downhole_pressure, f])
                        else:
                            writer.writerow([t, et, p, f])
                except UnboundLocalError: # either p or f was never assigned, or was unplugged
                    messagebox.showerror("Error","Please ensure that all sensors are properly connected.")
                    plt.close(fig)
                    return
                
                x_data.append(et)
                p_data.append(p)
                if dual_pressure:
                    dhp_data.append(downhole_pressure)
                if dual_flow:
                    f_data.append(f1)
                    f_data2.append(f2)
                else:
                    f_data.append(f)
                if dual_flow:
                    if f1 > f_max and not f_max_entered and not manual_f_ylim:
                        f_max = f1+5
                        ax2.set_ylim(f_min, f_max)
                    if f2 > f_max and not f_max_entered and not manual_f_ylim:
                        f_max = f2+5
                        ax2.set_ylim(f_min, f_max)
                    if f1 < f_min and not f_min_entered and not manual_f_ylim:
                        f_min = f1-5
                        ax2.set_ylim(f_min, f_max)
                    if f2 < f_min and not f_min_entered and not manual_f_ylim:
                        f_min = f2-5
                        ax2.set_ylim(f_min, f_max)
                else:
                    if f > f_max and not f_max_entered and not manual_f_ylim:
                        f_max = f+5
                        ax2.set_ylim(f_min, f_max)
                    if f < f_min and not f_min_entered and not manual_f_ylim:
                        f_min = f-5
                        ax2.set_ylim(f_min, f_max)
                if dual_pressure:
                    if downhole_pressure > p_max and not p_max_entered and not manual_p_ylim:
                        p_max = downhole_pressure+5
                    if downhole_pressure < p_min and not p_min_entered and not manual_p_ylim:
                        p_min = downhole_pressure-5
                if p > p_max and not p_max_entered and not manual_p_ylim:
                    p_max = p+5
                    ax1.set_ylim(p_min, p_max)
                if p < p_min and not p_min_entered and not manual_p_ylim:
                    p_min = p-5
                    ax1.set_ylim(p_min, p_max)

                # --- Keep sliding window ---
                if(sliding):
                    window_size = 300
                    if len(x_data) > window_size:
                        x_data = x_data[-window_size:]
                        p_data = p_data[-window_size:]
                        if dual_pressure:
                            dhp_data = dhp_data[-window_size:]
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
                if dual_pressure:
                    line_dhp.set_xdata(x_data)
                    line_dhp.set_ydata(dhp_data)
                if dual_flow:
                    line_f2.set_xdata(x_data)
                    line_f2.set_ydata(f_data2)
                if len(x_data) > 0:
                    ax1.set_xlim(min(x_data), max(x_data))
                # --- Update readouts ---
                if dual_flow:
                    flow_text.set_text(f"{f1:.2f}"+f_unit)
                    flow_text2.set_text(f"{f2:.2f}"+f_unit)

                elif dual_pressure:
                    dhp_text.set_text(f"{downhole_pressure:.2f}"+p_unit)
                    pressure_text.set_text(f"{p:.2f}"+p_unit)
                    flow_text.set_text(f"{f:.2f}"+f_unit)

                else:
                    flow_text.set_text(f"{f:.2f}")
                    pressure_text.set_text(f"{p:.2f}")
                
                plt.draw()
            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")
        fig.canvas.flush_events()
        time.sleep(0.01)
    plt.ioff()
    df = pd.read_csv(csv_path)
    # Create Excel file using xlsxwriter
    with pd.ExcelWriter(file_path, engine="xlsxwriter") as writer:
        workbook = writer.book
        worksheet = workbook.add_worksheet("Sheet1")
        writer.sheets["Sheet1"] = worksheet

        # --- Define formats ---
        header_format = workbook.add_format({
            'bold': True,
            'border': 1,
            'align': 'center',
            'valign': 'vcenter'
        })
        cell_format = workbook.add_format({
            'align': 'left',
            'valign': 'vcenter'
        })
        datetime_format = workbook.add_format({
            'num_format': 'yyyy-mm-dd hh:mm:ss',
            'bold':True,
            'border':1,
            'align':'center',
            'valign':'vcenter'
        })

        row = 0
        header_rows = [testnameheader, starttimeheader, pressureIDheader]
        if dual_pressure:
            header_rows.append(downholeIDheader)

        # --- Write multi-header rows ---
        for topheader in header_rows:
            for col, value in enumerate(topheader):
                if isinstance(value, pd.Timestamp) or isinstance(value, datetime):
                    worksheet.write_datetime(row, col, value, datetime_format)
                else:
                    worksheet.write(row, col, value, header_format)
            row += 1

        if dual_flow:
            for flow_header in [flowIDheader1, flowIDheader2]:
                for col, value in enumerate(flow_header):
                    worksheet.write(row, col, value, header_format)
                row += 1
        else:
            for col, value in enumerate(flowIDheader):
                worksheet.write(row, col, value, header_format)
            row += 1

        # --- Leave one empty row before data ---
        row += 1

        # --- Write data column titles row ---
        for col, value in enumerate(header):
            worksheet.write(row, col, value, header_format)
        row += 1  # Data starts here

        # --- Write main DataFrame rows ---
        for df_row in df.itertuples(index=False):
            for col, value in enumerate(df_row):
                worksheet.write(row, col, value, cell_format)
            row += 1

        header_lists = [testnameheader, starttimeheader, pressureIDheader]
        if dual_pressure:
            header_lists.append(downholeIDheader)

        # --- Auto-fit column widths ---
        for col_idx, col in enumerate(df.columns):
            all_data = list(df[col].astype(str))

            # Include multi-headers
            for header_list in header_lists:
                if col_idx < len(header_list):
                    all_data.append(str(header_list[col_idx]))

            if dual_flow:
                for flow_header in [flowIDheader1, flowIDheader2]:
                    if col_idx < len(flow_header):
                        all_data.append(str(flow_header[col_idx]))
            else:
                if col_idx < len(flowIDheader):
                    all_data.append(str(flowIDheader[col_idx]))

            # Include column title row
            if col_idx < len(header):
                all_data.append(str(header[col_idx]))

            max_len = max(len(str(x)) for x in all_data)
            worksheet.set_column(col_idx, col_idx, max_len + 2)  # Add small padding

        # --- Create dual-axis chart ---
        chart = workbook.add_chart({'type': 'scatter', 'subtype': 'straight_with_markers'})

        # Determine row ranges
        data_start_row = row - len(df)  # first row of data (zero-indexed)
        data_end_row = row - 1          # last row of data

        # --- X-axis values: Elapsed Time (s), numeric axis ---
        x_values_range = f"=Sheet1!$B${data_start_row + 1}:$B${data_end_row + 1}"

        # --- Flow series (secondary axis) ---
        if dual_flow:
            chart.add_series({
                'name':       'Pressure',
                'categories': x_values_range,
                'values':     f"=Sheet1!$C${data_start_row + 1}:$C${data_end_row + 1}",
                'y_axis':     0,            # primary axis
                'marker':     {'type': 'circle', 'size': 4},
                'line':       {'color': 'blue'}
            })
            chart.add_series({
                'name':       'Flow 1',
                'categories': x_values_range,
                'values':     f"=Sheet1!$D${data_start_row + 1}:$D${data_end_row + 1}",
                'y2_axis':    True,
                'marker':     {'type': 'square', 'size': 4},
                'line':       {'color': 'red'}
            })
            chart.add_series({
                'name':       'Flow 2',
                'categories': x_values_range,
                'values':     f"=Sheet1!$E${data_start_row + 1}:$E${data_end_row + 1}",
                'y2_axis':    True,
                'marker':     {'type': 'diamond', 'size': 4},
                'line':       {'color': 'orange'}
            })
        elif dual_pressure:
            chart.add_series({
                'name': 'Surface Pressure',
                'categories': x_values_range,
                'values': f"=Sheet1!$C${data_start_row+1}:$C${data_end_row+1}",
                'marker': {'type': 'circle', 'size': 4, 'fill': {'color': ipiblue}, 'border': {'color': ipiblue}},
                'line': {'color': ipiblue}
            })
            chart.add_series({
                'name': 'Downhole Pressure',
                'categories': x_values_range,
                'values': f"=Sheet1!$D${data_start_row+1}:$D${data_end_row+1}",
                'marker': {'type': 'diamond', 'size': 4, 'fill': {'color': darkblue}, 'border': {'color': darkblue}},
                'line': {'color': darkblue}
            })
            chart.add_series({
                'name': 'Flow',
                'categories': x_values_range,
                'values': f"=Sheet1!$E${data_start_row+1}:$E${data_end_row+1}",
                'y2_axis': True,
                'marker': {'type': 'square', 'size': 4, 'fill': {'color': 'orange'}, 'border': {'color': 'orange'}},
                'line': {'color': 'orange'}
            })
        else:
            chart.add_series({
                'name':       'Pressure',
                'categories': x_values_range,
                'values':     f"=Sheet1!$C${data_start_row + 1}:$C${data_end_row + 1}",
                'y_axis':     0,            # primary axis
                'marker':     {'type': 'circle', 'size': 4},
                'line':       {'color': 'blue'}
            })
            chart.add_series({
                'name': 'Flow',
                'categories': x_values_range,
                'values': f"=Sheet1!$D${data_start_row+1}:$D${data_end_row+1}",
                'y2_axis': True,
                'marker': {'type': 'square', 'size': 4},
                'line': {'color': 'orange'}
            })


        # --- Chart axes formatting ---
        chart.set_x_axis({
            'name': 'Elapsed Time (s)',
            'major_tick_mark': 'outside',
            'minor_tick_mark': 'none',
            'major_unit': 5,
            'minor_unit': 1,
            'min': 0,
            'major_gridlines': {'visible': False},
            'minor_gridlines': {'visible': False},
        })

        chart.set_y_axis({
            'name': 'Pressure ('+p_unit+')',
            'major_tick_mark': 'outside',
            'minor_tick_mark': 'none',
            'major_unit': 5,
            'major_gridlines': {'visible': False},
            'minor_gridlines': {'visible': False},
        })

        chart.set_y2_axis({
            'name': 'Flow Rate ('+f_unit+')',
            'major_tick_mark': 'outside',
            'minor_tick_mark': 'none',
            'major_unit': 5,
            'major_gridlines': {'visible': False},
            'minor_gridlines': {'visible': False},
        })

        # Legend
        chart.set_legend({'position': 'bottom'})
        
        # Title
        chart.set_title({'name':filename})

        # Insert chart into worksheet
        worksheet.insert_chart('G10', chart, {'x_scale': 1.5, 'y_scale': 1.5})

    # Remove the temporary CSV
    os.remove(csv_path)
    messagebox.showinfo("File Saved", f"File saved to:\n{file_path}") 

def testConnection(s: requests.Session): # check the ip for success response status code 200
    global eight_port
    payload = {"code":"request", "cid":-1, "adr":"gettree/deviceinfo/productcode/getdata"} 
    try:
        response = s.post(url, json=payload, timeout=2)
        response.raise_for_status()
        json = response.json()
        device_id = json.get("data", {}).get("value")
        if device_id != "AL1325" and device_id != "AL1324":
            eight_port = True
        return True
    except:
        return False
    
def save_settings(settings_dict: dict):
    print(f"-- REAL CACHE DIR: {CACHE_DIR.resolve()}")
    print(f"-- REAL CACHE FILE: {CACHE_FILE.resolve()}")
    try: 
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(settings_dict, f, indent=4)
    except Exception as e:
        messagebox.showerror("Settings Not Saved", "Your settings were unable to be saved for future tests.")

def load_last_settings() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

if __name__ == "__main__":
    try:
        if pyi_splash.is_alive():
            pyi_splash.close()
    except Exception:
        pass
    session = requests.Session()
    if testConnection(session):
        while True:
            settings = combinedWindow()
            if not settings:
                break
            live_plot()
            restart = messagebox.askyesno(
                "Run Another Test",
                "Would you like to start another test?"
            )
            if not restart:
                break
    else:
        messagebox.showerror("Error: Failed to Connect", "Unable to locate IPI Flow Skid. Ensure you are connected to the provided router (IPI DFM).")