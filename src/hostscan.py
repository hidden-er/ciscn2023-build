from scapy.all import IP, ICMP, sr1
import ipaddress
import threading
import warnings
warnings.filterwarnings("ignore")

class HostScan(object):
    def __init__(self, net: ipaddress.IPv4Network, timeout=5):
        self.net = net
        self.hosts = list(map(str, net.hosts()))
        self.count = len(self.hosts)
        self.timeout = timeout
        self.activelist = []

    def icmp_echo_test(self, dst: str) -> bool:
        res = sr1(IP(dst=dst) / ICMP(type=8),
                  timeout=self.timeout, verbose=False)
        if res and res[ICMP].type == 0:
            #print("[HostScan]{} is alive with icmp echo request".format(dst))
            return True
        return False

    def icmp_timestamp_test(self, dst: str) -> bool:
        res = sr1(IP(dst=dst) / ICMP(type=13),
                  timeout=self.timeout, verbose=False)
        if res and res[ICMP].type == 14:
            #print("[HostScan]{} is alive with icmp timestamp request".format(dst))
            return True
        return False

    def active_scan(self, dst: str):
        if self.icmp_echo_test(dst) or self.icmp_timestamp_test(dst):
            self.activelist.append(dst)

    def scan(self) -> list:
        self.activelist = []
        threads = []
        for i in range(self.count):
            t = threading.Thread(target=self.active_scan,
                                 args=(self.hosts[i],))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        #print("[HostScan]Scan finished")
        return self.activelist

def build_initial_result(result,res):
    for i in res:
        #print(result.get(i))
        if result.get(i) is None:
            result[i] = {}
            result[i]["services"] = []
            result[i]["deviceinfo"] = None
            result[i]["honeypot"] = None
            print("[HostScan]new ip {} add".format(i))
    return result

if __name__ == "__main__":
    result={}
    net = ipaddress.IPv4Network("103.252.118.0/24")
    hs = HostScan(net)
    res = hs.scan()
    print(build_initial_result(result,res))
