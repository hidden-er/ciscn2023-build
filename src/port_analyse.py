import json
from collections import defaultdict

#data = open("./result/result1.1.json",'r').read()
data=open("host_port.json",'r').read()
parsed_data = json.loads(data)

# 创建字典存储结果
port_counts = defaultdict(int)
protocol_counts = defaultdict(int)
port_protocol_counts = defaultdict(int)

for ip, info in parsed_data.items():
    services = info.get('services', [])
    for service in services:
        port = service.get('port')
        protocol = service.get('protocol')

        if port is not None:
            port_counts[port] += 1
            port_protocol_counts[(port, protocol)] += 1

        if protocol is not None:
            protocol_counts[protocol] += 1

print('Port counts:')
for port, count in port_counts.items():
    print(f'Port {port}: {count} times')

print('\nProtocol counts:')
for protocol, count in protocol_counts.items():
    print(f'Protocol {protocol}: {count} times')

print('\nPort and protocol counts:')
for (port, protocol), count in port_protocol_counts.items():
    print(f'Port {port} with protocol {protocol}: {count} times')
