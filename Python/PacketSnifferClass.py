import socket, json
from struct import *
from SignatureClass import Signatures

#CONSTANTS
PRINT = False

class Sniffer:
    global PRINT
    packet_id = 0
    def __init__(self, packet, config, os):
        self.config = config
        self.currentPacket = {}
        self.packet = packet
        self.os = os
        # self.PROTOCOL_DICT = {1:"ICMP"}
        # self.PROTOCOL_DICT = {6:"TCP"}
        # self.PROTOCOL_DICT = {17:"UDP"}
        self.PROTOCOL_DICT = {1:"ICMP", 6:"TCP", 17:"UDP"}
        self.attack = {"dping": 0, "dsyn": 0, "dudp": 0, "ddping": 0, "ddsyn": 0, "ddudp": 0}

    # --------------------Ethernet Frame----------------------------
    def ethernetFrameExtract(self, packet):
        dest_mac_addr, src_mac_addr, ether_type = unpack("! 6s 6s H", packet[:14])
        self.currentPacket['dest_mac'] = self.convertBytestoType(dest_mac_addr, "MAC")
        self.currentPacket['src_mac'] = self.convertBytestoType(src_mac_addr, "MAC")
        self.currentPacket['ether_type'] = socket.htons(ether_type)
        if self.currentPacket['ether_type'] == 8:
            return packet[14:]
        else:
            return None

    def printEthernetFrame(self):
        print("Ethernet Frame:")
        print("|-Destination Mac Address: {} \n"
              "|-Source Mac Address: {} \n"
              "|-EtherType: {}".format(self.currentPacket['dest_mac'],
                                       self.currentPacket['src_mac'],
                                       self.currentPacket['ether_type']))

    # -----------------------IP Packet------------------------------
    def IPPacketExtract(self, packet):
        version_and_header_length, self.currentPacket['time_to_live'], self.currentPacket['protocol'], src_ip_addr, dest_ip_addr = \
            unpack("! B 7x B B 2x 4s 4s",packet[:20])
        self.currentPacket['src_ip_addr'] = self.convertBytestoType(src_ip_addr, "IP")
        self.currentPacket['dest_ip_addr'] = self.convertBytestoType(dest_ip_addr, "IP")
        # Seperating Version and Header Length
        self.currentPacket['version'] = version_and_header_length >> 4
        self.currentPacket['header_length'] = (version_and_header_length & 15) * 4  # 4 because 4 bytes of a word(32-bit).
        if self.currentPacket['protocol'] in self.PROTOCOL_DICT.keys():
            self.currentPacket['protocol_name'] = self.PROTOCOL_DICT[self.currentPacket['protocol']]
            if self.os == "LINUX": self.printEthernetFrame()
            if PRINT or self.os == "LINUX": self.printIPPacket()
            return packet[self.currentPacket['header_length']:]
        else:
            return None

    def printIPPacket(self):
        print("|-IP Packet:")
        print(" |--Version: {}\n"
              " |--Header Length: {} bytes\n"
              " |--Time to Live: {} seconds\n"
              " |--Protocol: {}\n"
              " |--Source IP Address: {}\n"
              " |--Destination IP Address: {}".format(self.currentPacket['version'],
                                                      self.currentPacket['header_length'],
                                                      self.currentPacket['time_to_live'],
                                                      self.currentPacket['protocol'],
                                                      self.currentPacket['src_ip_addr'],
                                                      self.currentPacket['dest_ip_addr']))

    # -----------------------ICMP Packet------------------------------
    def ICMPPacketExtract(self, packet):
        self.currentPacket['type_icmp'], self.currentPacket['code'], self.currentPacket['sequence_number'] = unpack("! B B 4x H", packet[:8])
        if PRINT or self.os == "LINUX": self.printICMPPacket()
        return packet[8:]

    def printICMPPacket(self):
        TYPE_STR = {8: "Request", 0: "Reply", 3: "Error"}
        print(" |--ICMP Packet:")
        print("   |--Type: {} - {}\n"
              "   |--Code: {}\n"
              "   |--Sequence Number: {}\n".format(self.currentPacket['type_icmp'], TYPE_STR[self.currentPacket['type_icmp']], self.currentPacket['code'], self.currentPacket['sequence_number']))

    # -----------------------TCP Packet------------------------------
    def TCPPacketExtract(self, packet):
        self.currentPacket['src_port'], self.currentPacket['dest_port'], self.currentPacket['seq_number'], self.currentPacket['ack_number'], data_offset_and_reserved, flags = \
            unpack("! H H I I B B 2x",packet[:16])
        self.currentPacket['header_length_tcp'] = (data_offset_and_reserved >> 4) * 4
        # flags variable contains 8 bits but Control bits are only 6 bits.
        flags = (flags & 63)
        self.currentPacket['URG_Flag'] = flags >> 5
        self.currentPacket['ACK_Flag'] = (flags & 16) >> 4
        self.currentPacket['PSH_Flag'] = (flags & 8) >> 3
        self.currentPacket['RST_Flag'] = (flags & 4) >> 2
        self.currentPacket['SYN_Flag'] = (flags & 2) >> 1
        self.currentPacket['FIN_Flag'] = flags & 1
        if PRINT or self.os == "LINUX": self.printTCPPacket()
        return packet[self.currentPacket['header_length_tcp']:]

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
              "   |--FIN Flag: {}\n".format(self.currentPacket['src_port'], self.currentPacket['dest_port'], self.currentPacket['seq_number'], self.currentPacket['ack_number'],
                                            self.currentPacket['header_length_tcp'], self.currentPacket['URG_Flag'], self.currentPacket['ACK_Flag'], self.currentPacket['PSH_Flag'],
                                            self.currentPacket['RST_Flag'], self.currentPacket['SYN_Flag'], self.currentPacket['FIN_Flag']))

    # -----------------------UDP Packet------------------------------
    def UDPPacketExtract(self, packet):
        self.currentPacket['src_port'], self.currentPacket['dest_port'], self.currentPacket['UDP_len'] = unpack("! H H H 2x", packet[:8])
        if PRINT or self.os == "LINUX": self.printUDPPacket()
        return packet[8:]

    def printUDPPacket(self):
        print(" |--UDP Packet:")
        print("   |--Source Port: {}\n"
              "   |--Destination Port: {}\n"
              "   |--Data Length: {} bits\n".format(self.currentPacket['src_port'], self.currentPacket['dest_port'], self.currentPacket['UDP_len']))

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
        self.currentPacket['pacID'] = (Sniffer.packet_id + 1)
        if self.os == "LINUX":
            IP_Packet = self.ethernetFrameExtract(self.packet)
            if IP_Packet != None:
                protocol_packet = self.IPPacketExtract(IP_Packet)
                sign_object = Signatures(self.currentPacket['src_mac'], self.currentPacket['dest_mac'], self.currentPacket['src_ip_addr'], self.currentPacket['dest_ip_addr'])
            else:
                protocol_packet = None
        elif self.os == "WIN":
            protocol_packet = self.IPPacketExtract(self.packet)
            sign_object = Signatures(None, None, self.currentPacket['src_ip_addr'], self.currentPacket['dest_ip_addr'])
        # Capturing only ICMP, TCP and UDP packets for now.
        if protocol_packet != None:
            # ICMP Packet
            if self.currentPacket['protocol'] == 1:
                remaining_data = self.ICMPPacketExtract(protocol_packet)
                if self.currentPacket['type_icmp'] == 8: #Only Request
                    if self.config["DOS"]["ping"]["status"] == True:
                        sign_object.DenialOfService("ping", self.config["DOS"]["ping"]["threshold"], self.config["DOS"]["ping"]["timeinterval"])
                    if self.config["DDOS"]["ping"]["status"] == True:
                        sign_object.DistrubutedDOS("ping", self.config["DOS"]["ping"]["status"],self.config["DDOS"]["ping"]["threshold"], self.config["DDOS"]["ping"]["timeinterval"])
            # TCP Packet
            elif self.currentPacket['protocol'] == 6:
                remaining_data = self.TCPPacketExtract(protocol_packet)
                if self.currentPacket['SYN_Flag'] == 1 and self.currentPacket['URG_Flag'] == 0 and self.currentPacket['ACK_Flag'] == 0 and \
                        self.currentPacket['PSH_Flag'] == 0 and self.currentPacket['RST_Flag'] == 0 and self.currentPacket['FIN_Flag'] ==0: #Only SYN Flag
                    if self.config["DOS"]["syn"]["status"] == True:
                        sign_object.DenialOfService("syn", self.config["DOS"]["syn"]["threshold"], self.config["DOS"]["syn"]["timeinterval"])
                    if self.config["DDOS"]["syn"]["status"] == True:
                        sign_object.DistrubutedDOS("syn", self.config["DOS"]["syn"]["status"],self.config["DDOS"]["syn"]["threshold"], self.config["DDOS"]["syn"]["timeinterval"])
                if self.currentPacket['src_port'] == 21 and self.config["FTP"]["status"]:
                    bytes = "530 User cannot log in.".encode()
                    if bytes in remaining_data:
                        sign_object.FTPBruteForce(self.config["FTP"]["threshold"], self.config["FTP"]["timeinterval"])
            # UDP Packet
            elif self.currentPacket['protocol'] == 17:
                remaining_data = self.UDPPacketExtract(protocol_packet)
                if self.config["DOS"]["udp"]["status"] == True:
                    sign_object.DenialOfService("udp", self.config["DOS"]["udp"]["threshold"], self.config["DOS"]["udp"]["timeinterval"])
                if self.config["DDOS"]["udp"]["status"] == True:
                    sign_object.DistrubutedDOS("udp", self.config["DOS"]["udp"]["status"] ,self.config["DDOS"]["udp"]["threshold"], self.config["DDOS"]["udp"]["timeinterval"])
            # For Fetching on Double Click
            if self.os == "WIN":
                storedData = None
                try:
                    with open('./PacketLog.json','r') as file:
                        storedData = json.load(file)
                    storedData["Packets"].append(self.currentPacket)
                except:
                    pass
                if storedData != None:
                    with open('./PacketLog.json','w') as file:
                        json.dump(storedData, file)
            if sign_object.dos_attack == None and sign_object.ddos_attack == None:
                return []
            elif sign_object.ddos_attack != None:
                return sign_object.ddos_attack
            elif sign_object.dos_attack != None:
                return sign_object.dos_attack
        return None

    def appendRowToGUI(self):
        Sniffer.packet_id = Sniffer.packet_id + 1
        row = [str(Sniffer.packet_id), str(self.currentPacket['src_ip_addr']), str(self.currentPacket['dest_ip_addr']),
               self.PROTOCOL_DICT[self.currentPacket['protocol']]]
        if self.currentPacket["protocol"] == 1:
            row.append("ICMP Type: {} (Request)".format(self.currentPacket["type_icmp"])) if self.currentPacket["type_icmp"] == 8 else row.append("ICMP Reply")
        elif self.currentPacket["protocol"] == 6:
            row.append("Src. Port: {} -> Dest. Port: {}".format(self.currentPacket['src_port'],self.currentPacket['dest_port']))
        elif self.currentPacket["protocol"] == 17:
            row.append("Data: {} bits".format(self.currentPacket['UDP_len']))
        return row

    def logPacketToFile(self, index, filename, attacktype=None):
        file_obj = open("./"+str(filename), "a")
        row = None
        if self.os == "LINUX":
            if self.currentPacket['protocol'] == 1:
                row = "{}. {},{} --> {},{} IPv{} ICMP({}) type:{} code:{} seq_num:{}, {}\n".format(index, self.currentPacket['src_mac'], self.currentPacket['src_ip_addr'],
                                self.currentPacket['dest_mac'], self.currentPacket['dest_ip_addr'], self.currentPacket['version'], self.currentPacket['protocol'],
                                self.currentPacket['type_icmp'], self.currentPacket['code'], self.currentPacket['sequence_number'], attacktype)
            elif self.currentPacket['protocol'] == 6:
                row = "{}. {},{},{} --> {},{},{} IPv{} TCP({}) seq_num:{} ack_num:{} URG:{} ACK:{} PSH:{} RST:{} SYN:{} FIN:{}, {}\n".format(
                    index, self.currentPacket['src_mac'], self.currentPacket['src_ip_addr'], self.currentPacket['src_port'], self.currentPacket['dest_mac'],
                    self.currentPacket['dest_ip_addr'], self.currentPacket['dest_port'], self.currentPacket['version'], self.currentPacket['protocol'], self.currentPacket['seq_number'], self.currentPacket['ack_number'], self.currentPacket['URG_Flag'],
                    self.currentPacket['ACK_Flag'], self.currentPacket['PSH_Flag'], self.currentPacket['RST_Flag'], self.currentPacket['SYN_Flag'], self.currentPacket['FIN_Flag'], attacktype)
            elif self.currentPacket['protocol'] == 17:
                row = "{}. {},{},{} --> {},{},{} IPv{} UDP({}) data:{}bits, {}\n".format(
                    index, self.currentPacket['src_mac'], self.currentPacket['src_ip_addr'], self.currentPacket['src_port'], self.currentPacket['dest_mac'],
                    self.currentPacket['dest_ip_addr'], self.currentPacket['dest_port'], self.currentPacket['version'], self.currentPacket['protocol'], self.currentPacket['UDP_len'], attacktype)
        elif self.os == "WIN":
            if self.currentPacket['protocol'] == 1:
                row = "{}. {} --> {} IPv{} ICMP({}) type:{} code:{} seq_num:{}, {}\n".format(index, self.currentPacket['src_ip_addr'],
                                                                                          self.currentPacket['dest_ip_addr'], self.currentPacket['version'], self.currentPacket['protocol'],
                                                                                          self.currentPacket['type_icmp'], self.currentPacket['code'], self.currentPacket['sequence_number'], attacktype)
            elif self.currentPacket['protocol'] == 6:
                row = "{}. {},{} --> {},{} IPv{} TCP({}) seq_num:{} ack_num:{} URG:{} ACK:{} PSH:{} RST:{} SYN:{} FIN:{}, {}\n".format(
                    index, self.currentPacket['src_ip_addr'], self.currentPacket['src_port'],
                    self.currentPacket['dest_ip_addr'], self.currentPacket['dest_port'], self.currentPacket['version'], self.currentPacket['protocol'], self.currentPacket['seq_number'], self.currentPacket['ack_number'], self.currentPacket['URG_Flag'],
                    self.currentPacket['ACK_Flag'], self.currentPacket['PSH_Flag'], self.currentPacket['RST_Flag'], self.currentPacket['SYN_Flag'], self.currentPacket['FIN_Flag'], attacktype)
            elif self.currentPacket['protocol'] == 17:
                row = "{}. {},{} --> {},{} IPv{} UDP({}) data:{}bits, {}\n".format(
                    index, self.currentPacket['src_ip_addr'], self.currentPacket['src_port'],
                    self.currentPacket['dest_ip_addr'], self.currentPacket['dest_port'], self.currentPacket['version'], self.currentPacket['protocol'], self.currentPacket['UDP_len'],attacktype)
        if row != None:
            file_obj.write(row)