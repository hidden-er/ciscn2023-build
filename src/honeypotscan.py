import socks
import requests
import re
from proxies import proxy
import warnings
warnings.filterwarnings("ignore")

#https://mp.weixin.qq.com/s/hq-z2HBGz3nehnCVg_H-RQ
#返回内容形式为: xxxx/kippo 或 xxxx/HFish 或 xxxx/glastopf

'''
Kippo 是一个已经停止更新的经典的SSH蜜罐，使用了twisted来模拟SSH协议。
在kippo的最新版本中使用的是很老的twistd 15.1.0版本。该版本有个明显的特征。
在版本号交互阶段需要客户端的SSH版本为形如SSH-主版本-次版本 软件版本号，
当版本号为不支持的版本时，如SSH-1.9-OpenSSH_5.9p1就会报错“bad version 1.9”并且断开连接。
通过Kippo的配置来看，仅仅支持SSH-2.0-X和SSH-1.99-X两个主版本，其他主版本都会产生报错。
    后续又添加了一些其他特征和指纹，比较杂。
'''
def check_kippo(host, port):
    buffer_size = 1024

    try:
        s = socks.socksocket()
        s.settimeout(6.0)
        #s.set_proxy(socks.HTTP, '127.0.0.1', 7890)
        s.connect((host, port))

        banner = s.recv(buffer_size)

        try:
            s.send(b"SSH-2.1-OpenSSH_5.9p1\r\n")
            data = s.recv(buffer_size)
            if "bad version" in str(data):
                print(host,port,"kippo")
                return f"{port}/kippo"
            return None
        except:
            pass
    except:
        pass
        
    return None

'''
HFish和glastopf都是基于Python的蜜罐，都是使用了twisted来模拟HTTP协议。
HFish实现了一个WordPress登录页面，
页面中由一个名为x.js的javascript文件用来记录尝试爆破的登录名密码。
直接通过判断wordpress登录页是否存在x.js文件就可判断是否为蜜罐。
glastopf蜜罐，可以通过页面最下方的blog comments的输入框进行识别。
'''
def check_HFish_glastopf(host,port,https=False):
    matches = []
    if https:
        url = "https://" + host + ":" + str(port)
    else:
        url = "http://" + host + ":" + str(port)
    try:
        r = requests.get(url, timeout=6, proxies=proxy,verify=False)
        # r = requests.get(url, timeout=10, verify=False)
        content = str(r.headers) + r.text
        content = content.lower()
        verify_HFish=bool(re.search(r"(?<!\w)wordpress(?!\w)", content) and re.search(r'/static/x\.js', content))
        if verify_HFish:
            print(host, port, "HFish")
            return f"{port}/HFish"
        verify_glastopf = bool("<h2>blog comments</h2>" in content and "please post your comments for the blog" in content)
        if verify_glastopf:
            print(host, port, "glastopf")
            return f"{port}/glastopf"
        return None
    except:
        pass
    return matches

if __name__ == "__main__":
    print(check_kippo('185.139.228.48',2222))
    print(check_HFish_glastopf('103.94.234.117',9090))
    print(check_HFish_glastopf('130.102.0.50',8443,True))
