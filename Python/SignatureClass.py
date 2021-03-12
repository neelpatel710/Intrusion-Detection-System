import datetime

class Signatures:
    flood_type, ftp_login = {"ping": {}, "udp": {}, "syn": {}}, {}

    def __init__(self, src_mac, dst_mac, src_ip, dst_ip):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dos_attack = None
        self.ddos_attack = None
        self.ftp_attack = None

    def DenialOfService(self, flag, threshold, time_in_sec):
        time_diff = datetime.timedelta(seconds=time_in_sec)
        if self.src_ip not in Signatures.flood_type[flag].keys():
            Signatures.flood_type[flag][self.src_ip] = [1, datetime.datetime.now()]
        else:
            Signatures.flood_type[flag][self.src_ip][0] = Signatures.flood_type[flag][self.src_ip][0] + 1
            if Signatures.flood_type[flag][self.src_ip][0] >= threshold and Signatures.flood_type[flag][self.src_ip][1] <= (datetime.datetime.now() + time_diff):
                print("Alert! Denial of Service detected from IP: {} and TYPE: \"{}\"!".format(self.src_ip, flag.upper()))
                self.dos_attack = ["Denial of Service", self.src_ip, flag]
            elif Signatures.flood_type[flag][self.src_ip][0] < threshold and (datetime.datetime.now() > Signatures.flood_type[flag][self.src_ip][1] + time_diff):
                Signatures.flood_type[flag].pop(self.src_ip)
        print(Signatures.flood_type[flag],flag)

    def DistrubutedDOS(self, flag, dos_flag, threshold, time_in_sec):
        time_diff = datetime.timedelta(seconds=time_in_sec)
        if self.src_ip not in Signatures.flood_type[flag].keys():
            Signatures.flood_type[flag][self.src_ip] = [1, datetime.datetime.now()]
        else:
            if not dos_flag: Signatures.flood_type[flag][self.src_ip][0] = Signatures.flood_type[flag][self.src_ip][0] + 1
            if len(Signatures.flood_type[flag].keys()) > 1:
                total_sum = sum([i[0] for i in Signatures.flood_type[flag].values()])
                min_time = min([i[1] for i in Signatures.flood_type[flag].values()])
                if total_sum >= threshold and min_time <= (datetime.datetime.now() + time_diff):
                    print("Alert! Distributed Denial of Service detected on IP: {} and TYPE: \"{}\"!".format(self.dst_ip, flag.upper()))
                    self.dos_attack = ["Distributed Denial of Service", Signatures.flood_type[flag].keys(), flag]
                print(Signatures.flood_type[flag], flag)

    def FTPBruteForce(self, threshold, time_in_sec):
        time_diff = datetime.timedelta(seconds=time_in_sec)
        if self.dst_ip not in Signatures.ftp_login.keys():
            Signatures.ftp_login[self.dst_ip] = [1, datetime.datetime.now()]
        else:
            Signatures.ftp_login[self.dst_ip][0] = Signatures.ftp_login[self.dst_ip][0] + 1
            if Signatures.ftp_login[self.dst_ip][0] >= threshold and Signatures.ftp_login[self.dst_ip][1] <= (datetime.datetime.now() + time_diff):
                print("Alert! FTP Brute Force Login detected from IP: {}!".format(self.dst_ip))
                self.dos_attack = ["FTP Brute Force Attack", self.dst_ip]
            elif Signatures.ftp_login[self.dst_ip][0] < threshold and (datetime.datetime.now() > Signatures.ftp_login[self.dst_ip][1] + time_diff):
                Signatures.ftp_login.pop(self.dst_ip)
        print(Signatures.ftp_login)