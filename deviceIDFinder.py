import requests

url = "http://192.168.50.10/iolinkmaster"

def findDevice(portNum): # id device by IoT deviceID
        deviceIDs = {
            2015: ["Keyence FD-H10 Flow Meter", "f","images/key_flow_img.jpg"],
            1463: ["SU8021 IFM Flow Meter", "f","images/ifm_flow_img.jpg"],
            452:  ["PN7692 IFM Pressure Sensor", "p","images/ifm_pressure_img.jpg"],
            1313: ["EIO344 IFM Moneo Blue|Classic Adapter", None,"images/ifm_moneo_img.jpg"],
            2016: ["Keyence FD-H20 Flow Meter", "f", "images/key_flow_img.jpg"],
            2008: ["Keyence GPM400-T", "p", "images/key_pressure_img.jpg"],
            450: ["PN7670 IFM Pressure Sensor", "p", "images/ifm_high_pressure_img.jpg"]
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