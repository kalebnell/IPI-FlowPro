import requests
url = "http://192.168.50.10/iolinkmaster"
PORT1_PAYLOAD = {"code": "request","cid":-1,"adr":"/iolinkmaster/port[1]/iolinkdevice/pdin/getdata"}

def decode(raw_hex):
    return

try:
    portrequest = requests.post(url, json=PORT1_PAYLOAD, verify=False)
    portrequest.raise_for_status()
    json_data = portrequest.json()
    raw_hex = json_data.get("data", {}).get("value")
    print(json_data)
    results = decode(raw_hex)
except Exception as e:
    print("Port detection failed: {e}")

print(results)


