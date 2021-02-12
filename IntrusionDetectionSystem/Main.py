from PacketSnifferClass import Sniffer
import platform
import socket

if platform.system().lower() == "windows":
    print("OS Base Detected: %s" %platform.system())
    OSNAME = "WIN"
elif platform.system().lower() == "linux":
    print("OS Base Detected: %s" %platform.system())
    OSNAME = "LINUX"

#CONSTANTS
START = True

def main():
    if OSNAME == "WIN":
        HOST = socket.gethostbyname(socket.gethostname())
        print("Interface IP: %s" % HOST)
        # Create a raw socket and bind it to the public interface
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((HOST, 0))
        # Include IP headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Promiscuous mode - Enabled
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    elif OSNAME == "LINUX":
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    # Capturing Raw Packets
    i=0
    while i<500 and START:
        raw_packet, IPaddr = s.recvfrom(65536)
        ps_object = Sniffer(raw_packet, OSNAME)
        if ps_object.capturePacket() == 0:
            i= i + 1

    if OSNAME == "WIN":
        # Promiscuous mode - Disabled
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()