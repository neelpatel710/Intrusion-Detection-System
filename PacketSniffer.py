import socket
from struct import *
import sys

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

def ICMPPacketExtract(packet):
	type_icmp, code, sequence_number = unpack("! B B 4x H", packet[:8])
	printICMPPacket(type_icmp, code, sequence_number)
	return packet[8:]

def TCPPacketExtract(packet):
	src_port, dest_port, seq_number, ack_number, data_offset_and_reserved,flags = unpack("! H H I I B B 2x", packet[:16])
	header_length = (data_offset_and_reserved >> 4) * 4
	# flags variable contains 8 bits but Control bits are only 6 bits.
	flags = (flags & 63)
	URG_Flag = flags >> 5
	ACK_Flag = (flags & 16) >> 4
	PSH_Flag = (flags & 8) >> 3
	RST_Flag = (flags & 4) >> 2
	SYN_Flag = (flags & 2) >> 1
	FIN_Flag = flags & 1
	printTCPPacket(src_port, dest_port, seq_number, ack_number, header_length, URG_Flag, ACK_Flag,
				   PSH_Flag, RST_Flag, SYN_Flag, FIN_Flag)
	return packet[header_length:]

def UDPPacketExtract(packet):
	src_port, dest_port, UDPlen = unpack("! H H H 2x", packet[:8])
	printUDPPacket(src_port, dest_port, UDPlen)
	return packet[8:]

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
	print("|-Destination Mac Address: {} \n"
		  "|-Source Mac Address: {} \n"
		  "|-EtherType: {}".format(convertBytestoType(dest_mac_addr, "MAC"),
								   convertBytestoType(src_mac_addr, "MAC"),
								   socket.htons(ether_type)))
def printIPPacket(version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr):
	print("|-IP Packet:")
	print(" |--Version: {}\n"
		  " |--Header Length: {} bytes\n"
		  " |--Time to Live: {} seconds\n"
		  " |--Protocol: {}\n"
		  " |--Source IP Address: {}\n"
		  " |--Destination IP Address: {}".format(version,
													header_length,
													time_to_live,
													protocol,
													convertBytestoType(src_ip_addr, "IP"),
													convertBytestoType(dest_ip_addr, "IP")))

def printICMPPacket(type_icmp, code, sequence_number):
	TYPE_STR = {8: "Request", 0: "Reply"}
	print(" |--ICMP Packet:")
	print("   |--Type: {} - {}\n"
		  "   |--Code: {}\n"
		  "   |--Sequence Number: {}\n".format(type_icmp, TYPE_STR[type_icmp], code, sequence_number))

def printTCPPacket(src_port, dest_port, seq_number, ack_number, header_length, URG_Flag, ACK_Flag,
				   PSH_Flag, RST_Flag, SYN_Flag, FIN_Flag):
	print(" |--TCP Packet:")
	print("   |--Source Port: {}\n"
		  "   |--Destination Port: {}\n"
		  "   |--Sequence Number: {}\n"
		  "   |--Acknowlegdement Number: {}\n"
		  "   |--Header Length:{} Bytes\n"
		  "   |--URG Flag: {}\n"
		  "   |--ACK Flag: {}\n"
		  "   |--PSH Flag: {}\n"
		  "   |--RST Flag: {}\n"
		  "   |--SYN Flag: {}\n"
		  "   |--FIN Flag: {}\n".format(src_port, dest_port, seq_number, ack_number, header_length, URG_Flag, ACK_Flag,
				   PSH_Flag, RST_Flag, SYN_Flag, FIN_Flag))

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
	while i<15 and START:
		raw_packet, IPaddr = s.recvfrom(65536)
		if OSNAME == "LINUX":
			dest_mac_addr, src_mac_addr, ether_type, IP_Packet = ethernetFrameExtract(raw_packet)
			if socket.htons(ether_type) == 8:
				printEthernetFrame(dest_mac_addr,src_mac_addr,ether_type)
				version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr, protocol_packet = IPPacketExtract(IP_Packet)
		elif OSNAME == "WIN":
			version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr, protocol_packet = IPPacketExtract(raw_packet)
		# Capturing only ICMP, TCP and UDP packets for now.
		if protocol in [1,6]:
			printIPPacket(version, header_length, time_to_live, protocol, src_ip_addr, dest_ip_addr)
			# ICMP Packet
			if protocol == 1:
				remaining_data = ICMPPacketExtract(protocol_packet)
			# TCP Packet
			elif protocol == 6:
				remaining_data = TCPPacketExtract(protocol_packet)
			# print("      Data: {}".format(remaining_data))
			# # UDP Packet
			# elif protocol == 17:
			# 	print("{} Segment:", PROTOCOL_DICT[protocol])
			i+=1

	if OSNAME == "WIN":
		# Promiscuous mode - Disabled
		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()

