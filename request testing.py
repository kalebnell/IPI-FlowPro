port1 = None
port2 = None
port3=None
port4=None




def func1(portNum):
    globals()[f"port{portNum}"] = portNum

def func2():
    global port1,port2,port3,port4
    ports = [port1,port2,port3,port4]
    for port in ports:
        print(port)

func1(1)
func1(2)
func1(3)
func1(4)
func2()