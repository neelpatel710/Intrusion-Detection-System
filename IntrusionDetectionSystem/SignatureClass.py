import datetime

class Signatures:
    flood_type = {"ping": {}, "udp": {}, "syn": {}}

    def __init__(self, src_mac, dst_mac, src_ip, dst_ip):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def DenialOfService(self, flag, threshold, time_in_sec):
        time_diff = datetime.timedelta(seconds=time_in_sec)
        if self.src_ip not in Signatures.flood_type[flag].keys():
            Signatures.flood_type[flag][self.src_ip] = [1, datetime.datetime.now()]
        else:
            Signatures.flood_type[flag][self.src_ip][0] = Signatures.flood_type[flag][self.src_ip][0] + 1
            if Signatures.flood_type[flag][self.src_ip][0] >= threshold and Signatures.flood_type[flag][self.src_ip][1] <= (datetime.datetime.now() + time_diff):
                print("Alert! Denial of Service detected from IP: {} and TYPE: \"{}\"!".format(self.src_ip, flag.upper()))
                return 3
            elif Signatures.flood_type[flag][self.src_ip][0] < threshold and (datetime.datetime.now() > Signatures.flood_type[flag][self.src_ip][1] + time_diff):
                Signatures.flood_type[flag].pop(self.src_ip)
        return 0
        # print(Signatures.flood_type[flag])

    def DistrubutedDOS(self, flag, threshold, time_in_sec):
        time_diff = datetime.timedelta(seconds=time_in_sec)
        if len(Signatures.flood_type[flag].keys()) > 1:
            total_sum = sum([i[0] for i in Signatures.flood_type[flag].values()])
            min_time = min([i[1] for i in Signatures.flood_type[flag].values()])
            if total_sum >= threshold and min_time <= (datetime.datetime.now() + time_diff):
                print("Alert! Distributed Denial of Service detected on IP: {} and TYPE: \"{}\"!".format(self.dst_ip, flag.upper()))
                return 3
        return 0