from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP


def tcp_syn(dst, dport):
    pkt = IP(dst=dst) / TCP(flags='S', dport=dport)
    res = sr1(pkt, timeout=5, verbose=False)
    if res:
        # print(res)
        if res.haslayer(TCP):
            # print(res[TCP].flags)
            if res[TCP].flags == 'SA':  # SYN/ACK 若收到RST/ACK可能是会话异常关闭
                pkt = IP(dst=dst) / TCP(flags='R', dport=dport)
                send(pkt, verbose=False)
                return 'open'
            else:
                return 'closed'
        elif res[ICMP].type == 3 and res[ICMP].code in [1, 2, 3, 9, 10, 13]:
            # print(res[ICMP])
            return 'filtered'
        else:
            return 'unknown'
    else:
        return 'filtered'


if __name__ == '__main__':
    print(tcp_syn("103.252.118.8",443))
    '''
    dirpath = './hostscan/'  # 主机存活结果文件夹
    file_list = os.listdir(dirpath)
    file_list.sort()
    print(file_list)
    ip_list = []
    port_list = [21, 22, 23, 25, 53, 80, 81, 110, 111, 123, 135, 139, 389, 443, 445, 465, 500, 515, 548, 623, 636, 873,
                 902, 1080, 1099, 1433, 1521, 1883, 2049, 2181, 2202, 2222, 2375, 2379, 3128, 3306, 3389, 4730, 5222,
                 5432, 5555, 5601, 5672, 5900, 5938, 5984, 6000, 6379, 7001, 7077, 7547, 8080, 8081, 8443, 8545, 8686,
                 9000, 9001, 9042, 9092, 9100, 9200, 9418, 9999, 11211, 27017, 37777, 50000, 50070, 61616]
    for filename in file_list:
        f = open(dirpath + filename, 'r')
        for i in f:
            ip_list.append(i.strip())
        a = PortActiveScanner(ip_list)
        a.port_list = port_list
        a.scan()
        o = open(dirpath + 'ports/ActivePort' + filename[9:], 'w')
        for dst, dic in a.result.items():
            o.write(dst + ' ' + str(dic['open']) + '\n')
        f.close()
        o.close()
        print(filename + ' finished')
    '''
