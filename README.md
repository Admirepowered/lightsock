# lightsock
A light sock with Xor encryption  
Support UDP Method  
Recommended for personal use  
Need Python 3.6+  (Only)  
if you run servers , you Should set the server to 0.0.0.0  
TCP and UDP use the same port，Open the port you use  
Only test in Ubuntu 18.04 TLS and Windows 10 1809  
test in Python 3.8.1

服务器端部署
git clone https://github.com/Admirepowered/lightsock
cd lightsock/
在这里可以vi config.json 调整你的服务器设置（Server 0.0.0.0 port 自定  password 自定）
python3 sock4.py
可以使用Screen后台运行

也可以使用nohup

nohup python3 sock4.py >> sock.log 2>&1 &
使用ps -ef | grep python 查找进程号 kill -9 ID 即可杀掉进程

Windows客户端使用易语言Build（Ralase）的或者使用pyinstaller build的（不提供）
python sock4-local.py 自动读取config.json 并在本地建立一个（Server 你的服务器（可用域名） port 你的服务器端口 password 你设置的密码 localserver 0.0.0.0 localport 你的本地sock5监听端口）
Windows客户端使用命令行构建

Andriod的客户端正在构建
