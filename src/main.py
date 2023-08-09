import ipaddress
import json
from hostscan import HostScan,build_initial_result
from portscan import tcp_syn
from protocolscan import protocol_scan
from servicescan import web_scan,ssh_scan,mysql_scan
from honeypotscan import check_kippo,check_HFish_glastopf
from hardwarescan import HardwareIdentifier
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

'''
ip_list = [
'211.22.90.0/24',
'198.175.7.0/24',
'64.154.25.0/24',
'43.135.46.0/24',
'35.206.251.0/24',
'185.241.5.0/24',
'165.22.92.0/24',
'113.30.150.0/24',
'206.189.61.0/24',
'24.199.98.0/24',
'164.92.167.0/24',
'170.64.148.0/24',
'165.22.22.0/24',
'104.248.48.0/24',
'165.22.17.0/24',
'170.64.158.0/24',
'113.30.191.0/24',
'113.30.151.0/24',
'45.83.43.0/24',
'185.139.228.0/24',
'103.252.118.0/24',
'185.229.226.0/24',
'103.252.119.0/24',
'159.65.5.0/24',
'134.122.18.0/24',
'142.93.224.0/24',
'68.183.177.0/24',
'81.28.6.0/24',
'142.93.206.0/24',
'143.110.240.0/24',
'143.110.244.0/24',
'68.183.233.0/24',
'138.68.173.0/24',
'68.183.46.0/24',
'134.122.46.0/24',
'134.209.202.0/24',
'64.226.68.0/24',
'159.65.92.0/24',
'137.184.166.0/24',
'83.229.87.0/24'
]
'''

ip_list = ['45.83.43.0/24'] #demo

result = {}

#主机存活探测+初步结果格式生成,组件已完成
def host_supple(rawdata=None):
    if rawdata:
        data = json.loads(rawdata)
    else:
        data = {}

    for thing in ip_list:
        net = ipaddress.IPv4Network(thing)
        res = HostScan(net).scan()
        data = build_initial_result(data, res)

    with open('./result/host.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(data).encode("utf-8").decode('unicode_escape'))
    return json.dumps(data, indent=4, ensure_ascii=False)

#端口存活探测+结果填入,组件已完成
#支持多次扫描,每次的结果在上次的基础上填入且有去重
def port_supple(rawdata,supple=False,supple_port=None):
    if not supple:
        port_list = [443,80,21,8443,88,25,53,110,587,993,995,8080,143,465,81,22,8081,111,888,3389,5506,5000,2222,5672,2202,1022,15672]
    else:
        port_list = supple_port
    data=json.loads(rawdata)

    #i遍历IP,j遍历端口
    def process_service(i,j):
        content = tcp_syn(i,j)
        print(i,j,content)
        return i , j, content

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_service = {executor.submit(process_service, i, j): (i, j) for i in data for j in
                             port_list}

        for future in concurrent.futures.as_completed(future_to_service):
            i, j, supple = future.result()
            if supple == 'open':
                exist = False
                for k in range(len(data[i]["services"])):
                    if data[i]["services"][k]["port"] == j:
                        exist = True
                        break
                if not exist:
                    data[i]["services"].append({"port": j, "protocol": None, "service_app": None})

    with open('./result/host_port.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(data).encode("utf-8").decode('unicode_escape'))
    return json.dumps(data, indent=4, ensure_ascii=False)

def protocol_supple(rawdata):
    data=json.loads(rawdata)
    #i遍历IP,j遍历端口
    def process_service(i,j):
        content = protocol_scan(i,data[i]["services"][j]["port"])
        #print(i,data[i]["services"][j]["port"],content)
        return i , j, content

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_service = {executor.submit(process_service, i, j): (i, j) for i in data for j in
                             range(len(data[i]["services"]))}

        for future in concurrent.futures.as_completed(future_to_service):
            i, j, supple = future.result()
            if supple:
                data[i]["services"][j]["protocol"] = supple

    with open('./result/hp_protocol.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(data).encode("utf-8").decode('unicode_escape'))
    return json.dumps(data, indent=4, ensure_ascii=False)

#服务识别+结果填入,组件未完成;
#支持多次扫描,每次的结果在上次的基础上填入且有去重
def service_supple(rawdata):
    data=json.loads(rawdata)

    #i遍历IP,j遍历服务
    def process_service(i, j):
        service = data[i]["services"][j]
        if service["protocol"] != None:
            if "mysql" in service["protocol"]:
                return i, j, mysql_scan(i,service["port"])
        if service["protocol"] == "ssh":
            return i, j, ssh_scan(i,service["port"])
        if service["protocol"] == "http":
            return i, j, web_scan(fr'{i}:{service["port"]}')
        if service["protocol"] == "https":
            return i, j, web_scan(fr'{i}:{service["port"]}', True)
        return i, j, None

    with ThreadPoolExecutor() as executor:
        future_to_service = {executor.submit(process_service, i, j): (i, j) for i in data for j in
                             range(len(data[i]["services"]))}

        for future in concurrent.futures.as_completed(future_to_service):
            i, j, supple = future.result()
            if supple:
                if data[i]["services"][j]["service_app"] == None:
                    data[i]["services"][j]["service_app"] = []
                for k in range(len(supple)):
                    exist = False
                    for l in range(len(data[i]["services"][j]["service_app"])):
                        if data[i]["services"][j]["service_app"][l] == supple[k]:
                            exist = True
                            break
                    if not exist:
                        data[i]["services"][j]["service_app"].append(supple[k])

    with open('./result/hpp_service.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(data).encode("utf-8").decode('unicode_escape'))
    return json.dumps(data, indent=4, ensure_ascii=False)

#硬件识别+结果填入,组件已完成
def hardware_supple(rawdata):
    data=json.loads(rawdata)

    def process_service(i, j):
        service = data[i]["services"][j]
        if service["protocol"] == "http":
            return i, j, HardwareIdentifier(i,service["port"]).check_hardware()
        if service["protocol"] == "https":
            return i, j, HardwareIdentifier(i,service["port"],True).check_hardware()
        return i, j, None

    with ThreadPoolExecutor() as executor:
        future_to_service = {executor.submit(process_service, i, j): (i, j) for i in data for j in
                             range(len(data[i]["services"]))}

        for future in concurrent.futures.as_completed(future_to_service):
            i, j, supple = future.result()
            if supple!=None:
                data[i]["deviceinfo"]=supple

    #print(json.dumps(data, indent=4, ensure_ascii=False))
    with open('./result/hpps_device.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(data).encode("utf-8").decode('unicode_escape'))
    return json.dumps(data, indent=4, ensure_ascii=False)
#蜜罐识别+结果填入,组件已完成
def honeypot_supple(rawdata):
    data=json.loads(rawdata)

    def process_service(i, j):
        service = data[i]["services"][j]
        if service["protocol"] == "http":
            return i, j, check_HFish_glastopf(i,service["port"])
        if service["protocol"] == "https":
            return i, j, check_HFish_glastopf(i,service["port"],True)
        if service["protocol"] == "ssh":
            return i, j, check_kippo(i,service["port"])
        return i, j, None

    with ThreadPoolExecutor() as executor:
        future_to_service = {executor.submit(process_service, i, j): (i, j) for i in data for j in
                             range(len(data[i]["services"]))}

        for future in concurrent.futures.as_completed(future_to_service):
            i, j, supple = future.result()
            if supple!=None:
                if data[i]["honeypot"]==None:
                    data[i]["honeypot"]=[]
                data[i]["honeypot"].append(supple)

    #print(json.dumps(data, indent=4, ensure_ascii=False))
    with open('./result/final_result.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(data).encode("utf-8").decode('unicode_escape'))
    return json.dumps(data, indent=4, ensure_ascii=False)


host_supple()

with open('./result/host.json', encoding="utf-8") as f:
    rawdata = f.read()
port_supple(rawdata,True,[80,443,22,2222,5672,27017,6379,3306,8443]) #demo
#port_supple(rawdata)

with open('./result/host_port.json', encoding="utf-8") as f:
    rawdata = f.read()
protocol_supple(rawdata)

with open('./result/hp_protocol.json', encoding="utf-8") as f:
    rawdata = f.read()
service_supple(rawdata)

with open('./result/hpp_service.json', encoding="utf-8") as f:
    rawdata = f.read()
hardware_supple(rawdata)

with open('./result/hpps_device.json', encoding="utf-8") as f:
    rawdata = f.read()
honeypot_supple(rawdata)


