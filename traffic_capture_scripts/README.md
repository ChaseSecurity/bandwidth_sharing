## Note:
以此readme为准. (其他子文件夹里的注释和readme仅供参考, 没有即时更新.)

需要后台运行的话, 可以自行参考[关闭linux终端还让程序继续执行的方法](https://blog.csdn.net/beeworkshop/article/details/108610678)测试无问题后使用.  

- 一种方法是用`nohup command &`把脚本中命令(除了tcpdump和最后运行docker proxoy client的命令外)逐个运行
- 有tcpdump的命令用 `nohup sudo tcpdump ... ip .. &`
- 有运行proxy client的, 用命令`nohup docker ...honeygain or packetstream... 172... ... &`
- 用`ps -aux | grep tcpdump`可以查看对应的tcpdump是否在后台运行.
# Usage
### 首先测试脚本可以正常运行:
1. Make sure you can run docker and tcpdump command without inputing your password. 
    - E.g. 无需密码即可执行 `sudo tcpdump` 或者 `tcpdump`. 
    - 脚本测试过的环境是可以免密执行`docker ps`, `sudo tcpdump`

2. 在每个provider(packetstream, etc)对应的文件夹下, 分别运行对应指令:
      - packetstream: 
        - `./first_tcpdump_cap.sh 172.19.0.2 3 20 myServer` . 执行成功后tcpdump会开始在我们自定义的网络my_network上对172.19.0.2进行抓包, 每抓20秒存一个文件, 一共存完三个文件后停止抓包. 抓包文件的名字为`packetstream_myServer_year-month-day_hour-min-sec.pcap`. (抓包文件的命名格式为 `providerName_whereYouRunTheScript_year-month-day_hour-min-sec.pcap`
        - 上一条命令执行成功后, 执行 `./then_run_app.sh 172.19.0.2` . packetstream client开始在自定义网络my_network的172.19.0.2地址上开始运行.
        - 一分钟后两个脚本应该执行完毕. 且产生了三个抓包文件
      - honeygain:
        - `./first_tcpdump_cap.sh 172.19.0.3 3 20 myServer`
        - `./then_run_app.sh 172.19.0.3`
        - 注意⚠️: 如果要在多台服务器上运行honeygain, 其`then_run_app.sh`脚本中的最后一行参数`-device`必须使用一个不重复的名字.(不运行重名的active node)
      - iproyal:
        - `./first_tcpdump_cap.sh 172.19.0.4 3 20 myServer`
        - `./then_run_app.sh 172.19.0.4`
      - nanowire:
        - `./first_tcpdump_cap.sh 172.19.0.5 3 20 myServer`
        - `./then_run_app.sh 172.19.0.5`
   

### 正式抓数据
根据需要, 看是抓几个月的数据. 以3个月为例, 每天的数据都存一个文件.
Note: 这几个provider的运行命令的差别只在于赋的IP不同. My server is IUB server. You name this parameter based on where you run the scripts.
- packetstream: 
  - 先执行抓包脚本 `./first_tcpdump_cap.sh 172.19.0.2 90 86400 IUBServer`
  - 再运行client `then_run_app.sh 172.19.0.2`
- honeygain:
  ```
  ./first_tcpdump_cap.sh 172.19.0.3 90 86400 IUBServer
  
  ./then_run_app.sh 172.19.0.3
  ```
- iproyal:
  ```
  ./first_tcpdump_cap.sh 172.19.0.4 90 86400 IUBServer
  
  ./then_run_app.sh 172.19.0.4
  ```
- nanowire:
  ```
  ./first_tcpdump_cap.sh 172.19.0.5 90 86400 IUBServer
  
  ./then_run_app.sh 172.19.0.5
  ```

# How it works to capture the traffic we want. 

### 创建自定义网络, 设置固定IP
启动Docker容器的时候，使用默认的网络是不支持指派固定IP的

User specified IP address is supported on user defined networks only.

Create a user-defined network and specify available IP range 172.18.0.0/16 (As a sub-network, it must include a gateway and a broadcast address, which means: there must be more than 2 addresses in this sub-network so we can assign valid IP address for other use. With CIDR /30, num of ip addresses is 4)
```
~#docker network create --subnet=172.18.0.0/16 mynetwork
~#docker network ls
```
An example of assigning IP to a docker container. 
```
docker run -itd --name networkTest1 --net mynetwork --ip 172.18.0.2 centos:latest /bin/bash
```

### 抓包思路
- 先创建user defined network and specify IP range(usable IP的数量要超过准备跑的docker数量, 至少多两个. default is `172.8.0.0/16` which is basically sufficient.)
- tcpdump 在这个bridge interface上, 抓指定IP的包. Ps. bridge interface没法指定名字.
- Run the docker container on the assigned IP

### 抓包文件命名
providerName_whereYouRunTheScript_year-month-day_hour-min-sec.pcap`

e.g. `honeygain-iuasp-2022-05-27_14-01-48.pcap`

### Possible issues and solutions:
- Issue: `tcpdump: xxx.pcap: Permission denied`
  - Reason: The script is using tcpdump file rotation option, you may find tcpdump gets permissin denied to write to a new file. 
  That's because tcpdump drops privileges shortly after opening the first file specified for writing with `-w`. 
  - Sol: please make sure the directory you write into is world writable. You can make make the parent directory as well as all other sub-directories writable by `chmod -R a+w <directory>`
