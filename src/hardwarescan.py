import requests
from proxies import proxy
import warnings
warnings.filterwarnings("ignore")
'''
Hikivision-Webcam：
    访问 /index.asp，看响应头的Server字段，若为Hikvision-Webs则可确认
    访问 /doc/page/login.asp，看响应头的Server字段，若为DNVRS-Webs则可确认
dahua-Webcam：
    访问 /baseProj/images/favicon.ico ,如果标志存在且CONTENT-LENGTH为1150且存在自定义头字段P3P: CP=CAO PSA OUR，则可确认
cisco-switch：
    访问 / ,返回401且响应头存在关键词Cisco_CCSP_CWMP_TCPCR和Cisco-CcspCwmpTcpCR，则可确认
pfSense-firewall：
    访问 / 响应头和内容中存在pfSense即可确认
synology-Nas
    访问 / 响应头和内容中存在synology即可确认

后续又添加了一些其他特征和指纹，比较杂，就不写在这了。
'''
class HardwareIdentifier:
    def __init__(self, host, port, https=False):
        if https:
            self.base_url = f"https://{host}:{port}"
        else:
            self.base_url = f"http://{host}:{port}"
        self.session = requests.Session()
        #print(self.base_url)

    def check_hardware(self):
        result = self.check_hikivision()
        if result:
            return result
        result = self.check_dahua()
        if result:
            return result
        result = self.check_cisco()
        if result:
            return result
        result = self.check_pfsense()
        if result:
            return result
        result = self.check_synology()
        if result:
            return result
        return None

    def check_hikivision(self):
        try:
            response = self.session.get(self.base_url + '/index.asp',verify=False,proxies=proxy,timeout=6)
            if ('Hikvision-Webs' in response.headers.get('Server', '')):
                print(self.base_url, "webcam/hikvision")
                return ["webcam/hikvision"]
            response = self.session.get(self.base_url + '/doc/page/login.asp',verify=False,proxies=proxy,timeout=6)
            if ('DNVRS-Webs' in response.headers.get('Server', '')):
                print(self.base_url, "webcam/hikvision")
                return ["webcam/hikvision"]
            return None
        except Exception as e:
            return False

    def check_dahua(self):
        try:
            response = self.session.get(self.base_url + '/baseProj/images/favicon.ico',verify=False,proxies=proxy,timeout=6)
            if (response.headers.get('Content-Length') == '1150'):
                print(self.base_url,"webcam/dahua")
                return ["webcam/dahua"]
            return None
        except Exception as e:
            return False

    def check_cisco(self):
        try:
            response = self.session.get(self.base_url, verify=False, proxies=proxy,timeout=6)
            content=str(response.headers)
            if (response.status_code == 401 and 'Cisco_CCSP_CWMP_TCPCR' in content or 'Cisco-CcspCwmpTcpCR' in content):
                print(self.base_url, "switch/cisco")
                return ["switch/cisco"]
            if (response.status_code == 401 and 'cisco-IOS' in content):
                print(self.base_url, "switch/cisco")
                return ["switch/cisco"]
            return None
        except Exception as e:
            return False

    def check_pfsense(self):
        try:
            response = self.session.get(self.base_url,verify=False,proxies=proxy,timeout=6)
            content = str(response.headers).lower()+response.text.lower()
            if ('pfsense' in content):
                print(self.base_url, "firewall/pfsense")
                return ["firewall/pfsense"]
            return None
        except Exception as e:
            return False

    def check_synology(self):
        try:
            response = self.session.get(self.base_url,verify=False,proxies=proxy,timeout=6)
            content = str(response.headers).lower()+response.text.lower()
            if ('synology' in content):
                print(self.base_url, "nas/synology")
                return ["nas/synology"]
            return None
        except Exception as e:
            return False


if __name__ == "__main__":
    host="185.241.5.130"
    port=7547
    identifier = HardwareIdentifier(host,port,https=False).check_hardware()

