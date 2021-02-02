import socket
from struct import *
import sys
#Vinit
#Neel
#CONSTANTS
OSNAME = "WIN"
# OSNAME = "LINUX"
START = True
PROTOCOL_DICT = {1:"ICMP", 6:"TCP", 17:"UDP"}
# --------------------Ethernet Frame----------------------------
def ethernetFrameExtract(packet):
	dest_mac_addr, src_mac_addr, ether_type = unpack("! 6s 6s H", packet[:14])
	return dest_mac_addr, src_mac_addr, ether_type, packet[14:]

# -----------------------IP Packet------------------------------
def IPPacketExtract(packet):
	version_and_header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr = unpack("! B 7x B B 2x 4s 4s",packet[:20])
	# Seperating Version and Header Length
	version = version_and_header_length >> 4
	header_length = (version_and_header_length & 15) * 4 # 4 because 4 bytes of a word(32-bit).
	return version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr, packet[header_length:]

def convertBytestoType(byte_format, type):
	if type == "MAC":
		# '02x' - Lowercase Hex Format --- '02X' - Uppercase Hex Format
		six_octects = list(map("{:02X}".format, unpack("B B B B B B", byte_format)))
		# mac_format = ':'.join(six_octects)
		return ':'.join(six_octects)
	elif type == "IP":
		four_octects = list(map("{}".format, unpack("B B B B", byte_format)))
		return '.'.join(four_octects)
	else:
		return "Wrong Type!"

def printEthernetFrame(dest_mac_addr,src_mac_addr,ether_type):
	print("Ethernet Frame:")
	print("  Destination Mac Address: {} \n"
		  "  Source Mac Address: {} \n"
		  "  EtherType: {}".format(convertBytestoType(dest_mac_addr, "MAC"),
								   convertBytestoType(src_mac_addr, "MAC"),
								   socket.htons(ether_type)))
def printIPPacket(version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr):
	print("  IP Packet:")
	print("    Version: {}\n"
		  "    Header Length: {} bytes\n"
		  "    Time to Live: {} seconds\n"
		  "    Protocol: {}\n"
		  "    Source IP Address: {}\n"
		  "    Destination IP Address: {}\n".format(version,
													header_length,
													time_to_live,
													protocol,
													convertBytestoType(src_ip_addr, "IP"),
													convertBytestoType(dest_ip_addr, "IP")))
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
	while i<5 and START:
		raw_packet, IPaddr = s.recvfrom(65536)
		if OSNAME == "LINUX":
			dest_mac_addr, src_mac_addr, ether_type, IP_Packet = ethernetFrameExtract(raw_packet)
			if socket.htons(ether_type) == 8:
				printEthernetFrame(dest_mac_addr,src_mac_addr,ether_type)
				version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr, protocol_packet = IPPacketExtract(IP_Packet)
		elif OSNAME == "WIN":
			version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr, protocol_packet = IPPacketExtract(raw_packet)
		if protocol in PROTOCOL_DICT.keys():
			printIPPacket(version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr)
		i+=1

	if OSNAME == "WIN":
		# Promiscuous mode - Disabled
		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()

