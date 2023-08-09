import requests
import socket
import re

'''
为节省时间，常有端口协议直接给出。
对于某几个需要确定版本的协议,构造请求识别。
对于其他端口，为洁身时间，仅识别SSH和HTTP(s)
'''
def protocol_scan(ip,port):
    if port==80:
        return "http"
    if port==443:
        return "https"
    if port==21:
        return "ftp"
    if port==22:
        return "ssh"
    if port==23:
        return "telnet"
    if port==554:
        return "rtsp"
    if port==5672:
        return "amqp"
    if port==5671:
        return "amqp"
    if port==27017:
        return "mongodb"
    if port==6379:
        return "redis"
    if port==3306:
        #检查mysql版本
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, port))
            data = s.recv(1024)
            pattern = re.compile(r"(\d\.\d\.\d\d)")
            content = re.search(pattern, data.decode("ISO-8859-1"))
            print(data)
            if content:
                print(ip + ":" + str(port), ["mysql/" + content.group(1)])
                return "mysql/" + content.group(1)
            s.close()
        except Exception:
            # print(f'{url} 不使用 SSH 协议')
            pass
        return "mysql/N"

    url = ip + ":" + str(port)
    try:
        response = requests.get('https://' + url, timeout=5, verify=False)
        if response.status_code == 200:
            print(f'{url} 使用 HTTPS 协议')
            return "https"
    except Exception:
        pass

    try:
        response = requests.get('http://' + url, timeout=5)
        if "You're speaking plain HTTP to an SSL-enabled server port" in response.text:
            print(f'{url} 使用 HTTPS 协议')
            return "https"
        elif response.headers['content-type'] != None:
            print(f'{url} 使用 HTTP 协议')
            return "http"
    except Exception:
        #print(f'{url} 不使用 HTTP 或 HTTPS 协议')
        pass

    # 检查SSH协议
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        data = s.recv(1024)
        if "SSH" in data.decode().upper():
            print(f'{url} 使用 SSH 协议')
            return "ssh"
        s.close()
    except Exception:
        #print(f'{url} 不使用 SSH 协议')
        pass
    return None

if __name__ == '__main__':
    protocol_scan("43.135.46.213",3306)