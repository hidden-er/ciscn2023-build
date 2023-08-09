import requests
import re
import socks
from proxies import proxy
import warnings
warnings.filterwarnings("ignore")

#用于识别服务和服务版本的指纹库(正则表达式)
app_patterns = {
    'windows': [r"(?<!\w)windows(?!\w)"],
    'centos': [r"(?<!\w)centos(?!\w)"],
    'ubuntu': [r"(?<!\w)ubuntu(?!\w)"],
    'openssh': [r"(?<!\w)openssh(?!\w)"],
    'openssl': [r"(?<!\w)openssl(?!\w)"],
    'wordpress': [r"(?<!\w)wordpress(?!\w)"],
    'litespeed': [r"(?<!\w)litespeed(?!\w)"],
    'jetty': [r"(?<!\w)jetty(?!\w)"],
    'java': [r"(?<!\w)java(?!\w)",r'(tomcat)/([\d.]+)'],
    'node.js': [r"(?<!\w)node\.js(?!\w)",r"(?<!\w)express(?!\w)"],
    'express': [r"(?<!\w)express(?!\w)"],
    'asp.net': [r"(?<!\w)asp\.net(?!\w)"],
    'php': [r"(?<!\w)php(?!\w)",r"(?<!\w)phpsessid(?!\w)"],
    'microsoft-httpapi': [r"(?<!\w)microsoft-httpapi(?!\w)"],
    'rabbitmq': [r"(?<!\w)rabbitmq(?!\w)"],
    'apache': [r"(?<!\w)apache(?!\w)"],
    'iis': [r"(?<!\w)iis(?!\w)"],
    'nginx': [r"(?<!\w)nginx(?!\w)"],
    'micro_httpd': [r"(?<!\w)micro_httpd(?!\w)"],
    'openresty': [r"(?<!\w)openresty(?!\w)"],
    'grafana': [r"(?<!\w)grafana(?!\w)"],
    'weblogic': [r"(?<!\w)weblogic(?!\w)"],
    'elasticsearch': [r"(?<!\w)elasticsearch(?!\w)"],
    'debian': [r"(?<!\w)debian(?!\w)"]
}
version_patterns = {
    'windows': [r'windows ([\d.]+)', r'(windows)/([\d.]+)'],
    'centos': [r'(centos)/([\d.]+)'],
    'ubuntu': [r'(ubuntu)/([\d.]+)'],
    'openssh': [r'(openssh)/([\d.]+)'],
    'openssl': [r'(openssl)/([\d.]+)'],
    'wordpress': [r'(wordpress)/([\d.]+)',r'(wordpress) ([\d.]+)'],
    'litespeed': [r'(litespeed)/([\d.]+)',r'(litespeed cache) ([\d.]+)'],
    'jetty': [r'(jetty)/([\d.]+)'],
    'java': [r'(java)/([\d.]+)'],
    'node.js': [r'(node.js)/([\d.]+)'],
    'express': [r'(express)/([\d.]+)'],
    'asp.net': [r'(asp.net)/([\d.]+)'],
    'php': [r'(php)/([\d.]+)',r'(phpsessid)/([\d.]+)'],
    'microsoft-httpapi': [r'(microsoft-httpapi)/([\d.]+)'],
    'rabbitmq': [r'(rabbitmq)/([\d.]+)'],
    'apache': [r'(apache)/([\d.]+)', r'(apache)-coyote/([\d.]+)'],
    'iis': [r'(iis)/([\d.]+)'],
    'nginx': [r'(nginx)/([\d.]+)'],
    'micro_httpd': [r'(micro_httpd)/([\d.]+)'],
    'openresty': [r'(openresty)/([\d.]+)'],
    'grafana': [r'(grafana)/([\d.]+)'],
    'weblogic': [r'(weblogic)/([\d.]+)'],
    'elasticsearch': [r'(elasticsearch)/([\d.]+)',r'\"(lucene_version)\":\"([\d.]+)'],
    'debian': [r'(debian)/([\d.]+)']
}

#返回内容形式为 eg:["centos/N", "apache/2.2.15"]
def web_scan(url,https=False):
    matches = []
    if https:
        url = "https://" + url
    else:
        url = "http://" + url
    try:
        r = requests.get(url, timeout=10, verify=False, proxies=proxy)
        #r = requests.get(url, timeout=10, verify=False)
        content = str(r.headers) + r.text
        content = content.lower()

        #print(content)
        for app, patterns in app_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    matches.append(app)
                    break

        for i in range(len(matches)):
            patterns = version_patterns.get(matches[i], [fr'({matches[i]}/[\d.]+)'])
            #print(patterns)
            for pattern in patterns:
                x_version = re.search(pattern, content)
                if x_version:
                    matches[i] += '/' + x_version.group(2)
                    break


        for i in range(len(matches)):
            if "/" not in matches[i]:
                matches[i] += "/N"

        print(url,matches)

    except:
        pass
    return matches

#返回内容形式为 eg:["openssh/N"]
def ssh_scan(host, port):
    buffer_size = 1024
    result = []

    try:
        s = socks.socksocket()
        s.settimeout(6.0)
        #s.set_proxy(socks.HTTP, '127.0.0.1', 7890)
        s.connect((host, port))

        banner = s.recv(buffer_size)

        s.close()
        pattern = re.compile(r"(SSH-\d\.\d-OpenSSH_)(\d\.\d)")
        content = re.search(pattern, banner.decode())
        if content:
            print(host + ":" + str(port),["openssh/" + content.group(2)])
            result.append("openssh/" + content.group(2))
        pattern2 = re.compile(r"(Debian|Ubuntu)-(\d)")
        content2 = re.search(pattern2, banner.decode())
        if content2:
            print(host + ":" + str(port), [content2.group(1)])
            result.append(content2.group(1)+"/"+content2.group(2))
    except Exception:
        pass
    if result!=[]:
        return result
    return None


#返回内容形式为 eg:["openssh/N"]
def mysql_scan(host, port):
    buffer_size = 1024
    result = []

    try:
        s = socks.socksocket()
        s.settimeout(6.0)
        #s.set_proxy(socks.HTTP, '127.0.0.1', 7890)
        s.connect((host, port))

        banner = s.recv(buffer_size)
        s.close()
        pattern = re.compile(r"(ubuntu\d\.)(\d\d\.\d\d)(\.\d)")
        content = re.search(pattern, banner.decode("ISO-8859-1"))
        if content:
            print(host + ":" + str(port),["ubuntu/" + content.group(2)])
            result.append("ubuntu/" + content.group(2))
    except Exception:
        pass
    if result!=[]:
        return result
    return None

if __name__ == '__main__':
    print(ssh_scan("113.30.191.68",2222))
    #web_scan("165.22.22.193")
    '''
    web_scan("103.252.118.25:443",True)
    web_scan("159.65.92.42:443",True)
    web_scan("159.65.92.42")
    web_scan("113.30.191.229:443",True)
    web_scan("165.22.22.193") #不翻墙访问不了
    web_scan("103.252.119.251")
    web_scan("103.252.119.251:8083") #访问不了
    web_scan("103.252.119.251:9200")
    web_scan("185.139.228.48:8080")
    '''

    #web_scan("113.30.191.72:443",True) #php存疑
    #web_scan("24.199.98.197") #windows待修正
    #web_scan("24.199.98.138:7001") #7001好像可以直接鉴定为weblogic,待修正
    #web_scan("165.22.92.176:9200") #9200好像可以直接鉴定为elasticsearch,不过这个直接就能扫
    #web_scan("106.1.186.103")