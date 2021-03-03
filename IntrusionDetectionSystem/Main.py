import platform
from GUIClass import *

if platform.system().lower() == "windows":
    print("OS Base Detected: %s" %platform.system())
    OSNAME = "WIN"
elif platform.system().lower() == "linux":
    print("OS Base Detected: %s" %platform.system())
    OSNAME = "LINUX"

#CONSTANTS
START = True

def main():
    # Initializing the file.
    with open('./PacketLog.json','w') as file:
        json.dump({"Packets": []}, file)
    try:
        with open('./PacketLog.txt','r'):
            None
        with open('./PacketLog.txt','w') as file:
            json.load('',file)
    except:
        pass
    try:
        with open('./Config.json','r'):
            None
    except:
        default = {"DOS": {"ping":{"threshold": 10, "timeinterval": 60}, "syn":{"threshold": 50, "timeinterval": 60},
                           "udp":{"threshold": 50, "timeinterval": 60}},"DDOS": {"ping":{"threshold": 100, "timeinterval": 120},
                        "syn":{"threshold": 100, "timeinterval": 120}, "udp":{"threshold": 100, "timeinterval": 120}}, "logEnabled":True}
        with open('./Config.json','w') as file:
            json.dump(default,file)
    with open("./Config.json",'r') as file:
        fetchConfig = json.load(file)

    if OSNAME == "WIN":
        gui = GUI(fetchConfig)
    elif OSNAME == "LINUX":
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        while True:
            raw_packet, IPaddr = s.recvfrom(65536)
            ps_object = Sniffer(raw_packet, OSNAME)
            capture = ps_object.capturePacket()
            if capture == 0 or capture == 3:
                if fetchConfig["logEnabled"]: ps_object.logPacketToFile(index)
                index = index + 1

if __name__ == '__main__':
    main()