FROM python:3.7-slim-buster
WORKDIR /opt/app

RUN sed -i "s/http:\/\/deb.debian.org/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list
RUN sed -i "s/http:\/\/security.debian.org/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list

COPY src /opt/app/

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r /opt/app/requirements.txt --no-cache-dir 

cmd python -u /opt/app/main.py