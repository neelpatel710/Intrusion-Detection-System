import datetime

class Signatures:
    icmp_dict = {}
    def __init__(self, src_mac, dst_mac, src_ip, dst_ip):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def ICMPFlood(self, track_by, threshold, time_in_sec):
        time_diff = datetime.timedelta(seconds=time_in_sec)
        print(time_diff)
        print(Signatures.icmp_dict)
        print(datetime.datetime.now())
        if track_by == "src":
            if self.src_ip not in Signatures.icmp_dict.keys():
                Signatures.icmp_dict[self.src_ip] = [1, datetime.datetime.now() + time_diff]
                print(Signatures.icmp_dict[self.src_ip])
            else:
                Signatures.icmp_dict[self.src_ip][0] = Signatures.icmp_dict[self.src_ip][0] + 1
                if Signatures.icmp_dict[self.src_ip][0] >= threshold and datetime.datetime.now() <= Signatures.icmp_dict[self.dst_ip][1]:
                    print("Alert! Denial of Service detected from IP: {}!".format(self.src_ip))
                # elif Signatures.icmp_dict[self.src_ip][0] < threshold and datetime.datetime.now() > Signatures.icmp_dict[self.dst_ip][1]:
                #     Signatures.icmp_dict.pop(self.src_ip)
        print(Signatures.icmp_dict)

