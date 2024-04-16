# 版本更新
## 11/12/2022
增加了mail、url/_find、one_hour、cross_domain模块
## 11/9/2022
更正了out_json中对smtp处理时忘了统计长度的错误。。。只对domain_len模块有影响。
## 11/5/2022
更新了out_json模块，增加了里面对明文数据的读取（目前只有http和smtp），同时会兼容之前的版本。但要把_v2.json改为_v3.json以作区别。



# 脚本分布
## out_json  模块
- out_json.py  
  - 将pcap文件输出成json文件  
  - 1G的pcap文件大概需要10-15G内存,花费2-3h。
  - 会输出read.json统计已经读取过的pcap文件，再次输入会自动跳过  
  - 输出: $filename.pcap_v2.json
- out_json_all.sh  
  - 自动化调用out_json.py
  - 输入格式：bash out_json_all.sh path,对path目录下的所有pcap文件进行识别，并调用out_json.py进行处理。 
 - 建议对不同服务器抓到的流量创建新的文件夹分析，将脚本复制到新文件夹中，再运行。
 - 之后所有脚本的分析都基于该脚本输出的_v2.json文件。
- 示例: 
- ` bash out_json_all.sh /data2/bs/bs_traffic_cn/packetstream/packetstream_vps6/   `
- 如果文件太大，建议用tcpdump -r命令分割,并设置特殊的后缀,并在out_json_all.sh里修改读取的后缀。
- ` tcpdump -r filename.pcap -C 1000 -w filename_1000m.pcap `

## get_domain_len 模块
- get_domain_len.py  
  - 通过提取tls的sni域，http的host域，以及通过判断某个dns响应包之后的50个包里是否包含剩下的ip，进行统计流量。
  - 输出stat.json，通过json文件记录已经统计过的文件的信息。
  - 输出stat.txt,包含三个部分，流量分析结果，输入来源文件，域名长度排序。
- get_domain_len_all.sh
  - 自动化调用get_domain_len.py 
  - 输入格式：bash get_domain_len_all.sh path,对path目录下的所有_v2.json文件进行识别，get_domain_len.py进行处理。 
- 示例: 
- ` bash get_domain_len_all.sh /home/rhhuang/script/v5_stat/out_json/p_7 `
## get_time 模块  
- get_time.py  
  - 通过分析某个域名在某个时间段（默认是30s）出现的次数是否超过某个值（默认为5），以及在1分钟内是否超过10次（主要是避免两个30s交界处可能遗漏的探测。
  - time.json，通过json文件记录已经统计过的文件的信息。
  - time.txt,包含三个部分，以域名为标识，统计所有文件内出现次数多的流量，并记录对应的stream和timestamp。
  - time2.txt,包含三个部分，以文件为标识，统计该文件内出现次数多的域名的流量，并记录对应的stream和timestamp。
- get_time_all.sh
  - 自动化调用get_time.py 
  - 输入格式：bash get_time_all.sh path,对path目录下的所有_v2.json文件进行识别，get_time.py进行处理。 
- 示例: 
- ` bash get_time.sh /home/rhhuang/script/v5_stat/out_json/p_7 `

## port 模块
- no_find_port.py
  - 输入不需要看到的端口，得到其他端口的统计信息。
  - 输出port.json，通过json文件记录已经统计过的文件的信息。
  - 输出port.txt，里面包含某个域名（如果没有则显示ip）的所有端口以及长度信息，以及在对应文件内出现的长度。在json文件里有对应的timestamp，为了可读性，没有展示在该txt文件中。
  - 输出port2.txt，里面包含所有port，以及对应的所有域名（如果没有则显示ip）。在json文件里有对应的timestamp，为了可读性，没有展示在该txt文件中。
- port_all.sh
  - 自动化调用no_find_port.py 
  - 输入格式：bash port_all.sh path,对path目录下的所有_v2.json文件进行识别，no_find_port.py进行处理。
  - 在port_all.sh文件里的第9行进行编辑，以控制不需要看到的端口，如果不输出端口，则默认都需要看到。
- 示例: 
- ` bash port_all.sh /home/rhhuang/script/v5_stat/out_json/p_7 `
- find_port.py
  - 只是在原来的基础上修改了一点，可以输出想查找的端口。
  - 把port_all.sh 里对no_find_port.py的调用改成find_port.py就行了。
## sensitive_domain 模块
- get_sensitive_domain.py
  - 只是提取包含gov，edu字段的域名，以及无法识别域名的ip。
  - 输出stat.json。通过json文件记录已经统计过的文件的信息。
  - 输出stat.txt。统计所有无域名的ip，以及对应的端口。
  - 输出stat2.txt。统计所有包含gov，edu字段的域名。
- all.sh
  - 自动化调用get_sensitive_domain.py 
  - 输入格式：bash all.sh path,对path目录下的所有_v2.json文件进行识别，get_sensitive_domain.py进行处理。
- 示例: 
- ` bash all.sh /home/rhhuang/script/v5_stat/out_json/p_7 `

## mail 模块
- get_mail.py
  - 获得所有smtp的信息。需要使用_v3.json文件
  - 输出mail.json。通过json文件记录已经统计过的文件的信息。
  - 输出mail.txt。统计所有邮件服务器的ip，端口，发送方邮箱，接收方邮箱，以及所有收发邮件情况。
  - 输出mail2.txt。统计所有发送方，接收方，以及邮件内容。
  - 输出mail3.txt。统计所有邮件服务器，以及所有发送方邮件地址后缀，接收方邮件地址后缀。
- all.sh
  - 自动化调用get_mail.py 
  - 输入格式：bash all.sh path,对path目录下的所有_v3.json文件进行识别，get_mail.py进行处理。
- 示例: 
- ` bash all.sh /home/rhhuang/script/v5_stat/out_json/p_7 `

## one_hour 模块
- get_one_hour.py
  - 以1小时为单位，统计24小时内的流量分布。
  - 输出stat.json。通过json文件记录已经统计过的文件的信息。
  - 输出stat1.txt。统计所有不包括代理方流量的分布，然后是每小时所有出现的域名以及长度。
  - 输出stat2.txt。统计所有不包括代理方流量的分布。
  - 输出stat3.txt。统计每个域名在每个小时的流量长度以及占比。
- all.sh
  - 自动化调用get_one_hour.py 
  - 输入格式：bash all.sh path,对path目录下的所有_vx.json文件进行识别，get_one_hour.py进行处理。
- 示例: 
- ` bash all.sh /home/rhhuang/script/v5_stat/out_json/p_7 `

## cross_domain 模块
- find_cross_domain.py
  - 通过分析http的host域以及https的sni域，输出每条traffic下所有不同的域。（默认第一次出现的host就是真正的host）
  - 输出stat.json。通过json文件记录已经统计过的文件的信息。
  - 输出stat.txt。统计有不同host的域名，输出对应文件的stream，以及所涉及的协议。
- all.sh
  - 自动化调用find_cross_domain.py 
  - 输入格式：bash all.sh path,对path目录下的所有_vx.json文件进行识别，find_cross_domain.py进行处理。
- 示例: 
- ` bash all.sh /home/rhhuang/script/v5_stat/out_json/p_7 `

## url_find 模块
- url_find.py
  - 通过分析http的url以及https的sni域，统计所有带有关键字的host
  - 输出stat.json。通过json文件记录已经统计过的文件的信息。
  - 输出stat.txt。输出带有关键字的url/host，以及在文件中的stream
- all.sh
  - 自动化调用url_find.py 
  - 需要在对python调用的那行填入需要的关键字
  - 输入格式：bash all.sh path,对path目录下的所有_v3.json文件进行识别，url_find.py进行处理。
- 示例: 
- ` bash all.sh /home/rhhuang/script/v5_stat/out_json/p_7 `
