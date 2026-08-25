import requests
import time
import tkinter as tk
from tkinter import ttk, messagebox
import random
import bisect


url = "http://192.168.50.10/iolinkmaster"
PORT_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[8]/iolinkdevice/pdin/getdata"}

def decodeHighPressureIFM(raw_hex): # decode raw hex data from IFM high pressure sensor (PN7670)
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex,16), f'0{bit_len}b')[2:-2]
    bar = (float(int(bin_value,2)))
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

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

def decodeTC(raw_hex):
    data = bytes.fromhex(raw_hex)
    print(data)
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
    print(bin_value)
    bar = (float(int(bin_value, 2))) / 10
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]
    
def decode7602(raw_hex):
    bit_len = 4*len(raw_hex)
    bin_value = format(int(raw_hex, 16), f'0{bit_len}b')[0:16]
    print(bin_value)
    bar = (float(int(bin_value, 2))) / 100
    psi = bar * 14.5038
    Kpa = bar * 100
    return [bar, psi, Kpa]

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
            1067940: ["PA-23SXio Keller Pressure Sensor", "p", "images/keller.jpg"],
        }
        try:
            payload = {"code":"request","cid":-1,
                      "adr":f"/iolinkmaster/port[{portNum}]/iolinkdevice/deviceid/getdata"}
            portrequest = requests.post(url, json=PORT_PAYLOAD, verify=False)
            portrequest.raise_for_status()
            json_data = portrequest.json()
            id_val = json_data.get("data", {}).get("value")
            if id_val in deviceIDs.keys():
                return deviceIDs[id_val]
            else:
                return decodeKeller23SXio(id_val)
                #return id_val
        except Exception as e:
            print(f"Port {portNum} detection failed: {e}")
            return None



# a = [1,2,3,4,5,6,7,8,9,10]
# left = bisect.bisect_left(a, 1)
# right = bisect.bisect_right(a, 10)
# selected = slice(left, right)
# print(selected.start)





a = [1,2,3,4,5,6,7,8,9,10]
print(a[-5:])