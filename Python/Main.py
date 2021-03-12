import platform,json
from datetime import datetime
from MailClass import Mailer

if platform.system().lower() == "windows":
    from GUIClass import *
    print("OS Base Detected: %s" %platform.system())
    OSNAME = "WIN"
elif platform.system().lower() == "linux":
    print("OS Base Detected: %s" %platform.system())
    OSNAME = "LINUX"

# CONSTANTS
START = True

def main():
    # Initializing the file.
    try:
        with open('./Config.json','r'):
            pass
    except:
        default = {"DOS":
                       {"status":True,
                        "ping":{"threshold": 10, "timeinterval": 60, "status":True},
                        "syn":{"threshold": 50, "timeinterval": 60, "status":True},
                        "udp":{"threshold": 50, "timeinterval": 60, "status":True}},
                   "DDOS":
                       {"status":True,
                        "ping":{"threshold": 100, "timeinterval": 120, "status":True},
                        "syn":{"threshold": 100, "timeinterval": 120, "status":True},
                        "udp":{"threshold": 100, "timeinterval": 120, "status":True}},
                   "logEnabled":True,
                   "FTP":
                       {"status":True,
                        "threshold":3000, "timeinterval":120},
                   "Mail":
                       {"server":"smtp.gmail.com",
                        "serverport": 587,
                        "sender": "None",
                        "receiver": "None"}}

        with open('./Config.json','w') as file:
            json.dump(default,file)
    with open("./Config.json",'r') as file:
        fetchConfig = json.load(file)
    if OSNAME == "WIN":
        with open('./PacketLog.json','w') as file:
            json.dump({"Packets": []}, file)

        gui = GUI(fetchConfig)

    elif OSNAME == "LINUX":
        import socket
        from PacketSnifferClass import Sniffer
        if fetchConfig["logEnabled"] == True:
            format = "%d_%m_%Y_%H_%M_%S"
            logFileName = datetime.now().strftime(format)+".txt"
            with open('./'+str(logFileName), 'w'):
                pass
        else:
            logFileName = "None.txt"

        index=0
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        while True:
            raw_packet, IPaddr = s.recvfrom(65536)
            ps_object = Sniffer(raw_packet, fetchConfig, OSNAME)
            capture = ps_object.capturePacket()
            if bool(capture):
                if capture[0] == "Distributed Denial of Service":
                    mailer = Mailer(fetchConfig["Mail"])
                    mailer.send("Alert! Distributed Denial of Service detected from \nIP's: {}\nType: {} Flood!".format(', '.join(list(capture[1])), capture[2].upper()))
                if capture[0] == "Denial of Service":
                    mailer = Mailer(fetchConfig["Mail"])
                    mailer.send("Alert! Denial of Service detected from IP: {}\nType: {} Flood!".format(capture[1], capture[2].upper()))
                if capture[0] == "FTP Brute Force Attack":
                    mailer = Mailer(fetchConfig["Mail"])
                    mailer.send("Alert! FTP Login-Brute Force Attack detected from \nIP: {}!".format(capture[1]))
            if fetchConfig["logEnabled"] and not bool(capture) and capture != None:
                ps_object.logPacketToFile(index+1, logFileName)
            elif fetchConfig["logEnabled"] and bool(capture):
                ps_object.logPacketToFile(index+1, logFileName, "AttackPacket")
            index = index + 1

if __name__ == '__main__':
    main()