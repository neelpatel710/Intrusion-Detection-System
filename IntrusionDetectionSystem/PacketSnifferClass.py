import socket
from struct import *
from SignatureClass import Signatures

class Sniffer:
    def __init__(self, packet, os):
        self.packet = packet
        self.os = os
        self.PROTOCOL_DICT = {1:"ICMP", 6:"TCP", 17:"UDP"}

    # --------------------Ethernet Frame----------------------------
    def ethernetFrameExtract(self, packet):
        dest_mac_addr, src_mac_addr, ether_type = unpack("! 6s 6s H", packet[:14])
        self.dest_mac_addr = self.convertBytestoType(dest_mac_addr, "MAC")
        self.src_mac_addr = self.convertBytestoType(src_mac_addr, "MAC")
        self.ether_type = socket.htons(ether_type)
        if self.ether_type == 8:
            self.printEthernetFrame()
            return packet[14:]
        else:
            return None

    def printEthernetFrame(self):
        print("Ethernet Frame:")
        print("|-Destination Mac Address: {} \n"
              "|-Source Mac Address: {} \n"
              "|-EtherType: {}".format(self.dest_mac_addr,
                                       self.src_mac_addr,
                                       self.ether_type))

    # -----------------------IP Packet------------------------------
    def IPPacketExtract(self, packet):
        version_and_header_length, self.time_to_live, self.protocol, src_ip_addr, dest_ip_addr = \
            unpack("! B 7x B B 2x 4s 4s",packet[:20])
        self.src_ip_addr = self.convertBytestoType(src_ip_addr, "IP")
        self.dest_ip_addr = self.convertBytestoType(dest_ip_addr, "IP")
        # Seperating Version and Header Length
        self.version = version_and_header_length >> 4
        self.header_length = (version_and_header_length & 15) * 4  # 4 because 4 bytes of a word(32-bit).
        # if self.protocol in self.PROTOCOL_DICT.keys():
        if self.protocol in [1]:
            # if self.protocol in [6]:
            # if self.protocol in [17]:
            self.printIPPacket()
            return packet[self.header_length:]
        else:
            return None

    def printIPPacket(self):
        print("|-IP Packet:")
        print(" |--Version: {}\n"
              " |--Header Length: {} bytes\n"
              " |--Time to Live: {} seconds\n"
              " |--Protocol: {}\n"
              " |--Source IP Address: {}\n"
              " |--Destination IP Address: {}".format(self.version,
                                                      self.header_length,
                                                      self.time_to_live,
                                                      self.protocol,
                                                      self.src_ip_addr,
                                                      self.dest_ip_addr))

    # -----------------------ICMP Packet------------------------------
    def ICMPPacketExtract(self, packet):
        self.type_icmp, self.code, self.sequence_number = unpack("! B B 4x H", packet[:8])
        self.printICMPPacket()
        return packet[8:]

    def printICMPPacket(self):
        TYPE_STR = {8: "Request", 0: "Reply", 3: "Error"}
        print(" |--ICMP Packet:")
        print("   |--Type: {} - {}\n"
              "   |--Code: {}\n"
              "   |--Sequence Number: {}\n".format(self.type_icmp, TYPE_STR[self.type_icmp], self.code, self.sequence_number))

    # -----------------------TCP Packet------------------------------
    def TCPPacketExtract(self, packet):
        self.src_port, self.dest_port, self.seq_number, self.ack_number, data_offset_and_reserved, flags = \
            unpack("! H H I I B B 2x",packet[:16])
        self.header_length = (data_offset_and_reserved >> 4) * 4
        # flags variable contains 8 bits but Control bits are only 6 bits.
        flags = (flags & 63)
        self.URG_Flag = flags >> 5
        self.ACK_Flag = (flags & 16) >> 4
        self.PSH_Flag = (flags & 8) >> 3
        self.RST_Flag = (flags & 4) >> 2
        self.SYN_Flag = (flags & 2) >> 1
        self.FIN_Flag = flags & 1
        self.printTCPPacket()
        return packet[self.header_length:]

    def printTCPPacket(self):
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
              "   |--FIN Flag: {}\n".format(self.src_port, self.dest_port, self.seq_number, self.ack_number,
                                            self.header_length, self.URG_Flag, self.ACK_Flag, self.PSH_Flag,
                                            self.RST_Flag, self.SYN_Flag, self.FIN_Flag))

    # -----------------------UDP Packet------------------------------
    def UDPPacketExtract(self, packet):
        self.src_port, self.dest_port, self.UDP_len = unpack("! H H H 2x", packet[:8])
        self.printUDPPacket()
        return packet[8:]

    def printUDPPacket(self):
        print(" |--UDP Packet:")
        print("   |--Source Port: {}\n"
              "   |--Destination Port: {}\n"
              "   |--Data Length: {} bits\n".format(self.src_port, self.dest_port, self.UDP_len))

    # -----------------------Other Functions------------------------------
    def convertBytestoType(self, byte_format, type):
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

    def capturePacket(self):
        if self.os == "LINUX":
            IP_Packet = self.ethernetFrameExtract(self.packet)
            if IP_Packet != None:
                protocol_packet = self.IPPacketExtract(IP_Packet)
                sign_object = Signatures(self.src_mac_addr, self.dest_mac_addr, self.src_ip_addr, self.dest_ip_addr)
            else:
                protocol_packet = None
        elif self.os == "WIN":
            protocol_packet = self.IPPacketExtract(self.packet)
            sign_object = Signatures(None, None, self.src_ip_addr, self.dest_ip_addr)
        # Capturing only ICMP, TCP and UDP packets for now.
        if protocol_packet != None:
            # ICMP Packet
            if self.protocol == 1:
                remaining_data = self.ICMPPacketExtract(protocol_packet)
                if self.type_icmp == 8: #Only Request
                    sign_object.ICMPFlood(20, 120)
            # TCP Packet
            elif self.protocol == 6:
                remaining_data = self.TCPPacketExtract(protocol_packet)
                if self.SYN_Flag == 1 and self.URG_Flag == 0 and self.RST_Flag == 0 and self.PSH_Flag == 0 \
                    and self.FIN_Flag == 0 and self.ACK_Flag == 0:
                    sign_object.SYNFlood(20, 120)
            # # UDP Packet
            elif self.protocol == 17:
                remaining_data = self.UDPPacketExtract(protocol_packet)
            return 0
        return -1