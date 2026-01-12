import requests
import threading
import ipaddress
import matplotlib.pyplot as plt
from openpyxl.styles import Alignment
from matplotlib.widgets import Button
from matplotlib.patches import Rectangle
from datetime import datetime
import pandas as pd
import time
from matplotlib.gridspec import GridSpec
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sys
import os
from contextlib import suppress
import concurrent.futures
import subprocess
from PIL import Image, ImageTk
import os
import csv
import matplotlib.image as mpimg
from requests_toolbelt.adapters.source import SourceAddressAdapter

url = "http://10.0.0.2/iolinkmaster"

def findDevice(portNum): # id device by IoT deviceID
        deviceIDs = {
            2015: ["Keyence FD-H10 Flow Meter", "f","images/key_flow_img.jpg"],
            1463: ["SU8021 IFM Flow Meter", "f","images/ifm_flow_img.jpg"],
            452:  ["PN7692 IFM Pressure Sensor", "p","images/ifm_pressure_img.jpg"],
            1313: ["EIO344 IFM Moneo Blue|Classic Adapter", None,"images/ifm_moneo_img.jpg"],
            2016: ["Keyence FD-H20 Flow Meter", "f", "images/key_flow_img.jpg"]
            ### TODO Keyence Pressure Sensor intergration?
        }
        try:
            payload = {"code":"request","cid":-1,
                       "adr":f"/iolinkmaster/port[{portNum}]/iolinkdevice/deviceid/getdata"}
            portrequest = requests.post(url, json=payload, verify=False)
            portrequest.raise_for_status()
            json_data = portrequest.json()
            id_val = json_data.get("data", {}).get("value")
            return id_val
        except Exception as e:
            print(f"Port {portNum} detection failed: {e}")
            return None
        

print(findDevice(1))