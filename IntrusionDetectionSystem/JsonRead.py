import json
current = {'PacID': '1', 'time_to_live': '128', 'protocol': '6', 'src_ip_addr': '10.0.0.53', 'dest_ip_addr': '54.84.162.170', 'version': '4', 'header_length': '20', 'src_port': '51876', 'dest_port': '443', 'seq_number': '2816738823', 'ack_number': '2812127580', 'header_length_tcp': '20', 'URG_Flag': '0', 'ACK_Flag': '1', 'PSH_Flag': '0', 'RST_Flag': '0', 'SYN_Flag': '0', 'FIN_Flag': '0'}
try:
    with open('./PacketLog.json','r') as file:
        storedData = json.load(file)
except:
    with open('./PacketLog.json','w') as file:
        json.dump({"Packets": []}, file)
with open('./PacketLog.json','r') as file:
    storedData = json.load(file)
print(storedData)
storedData["Packets"].append(current)
with open('./PacketLog.json', 'w') as file:
    json.dump(storedData,file)