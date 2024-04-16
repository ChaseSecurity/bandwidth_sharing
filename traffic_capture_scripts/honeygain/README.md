`nohup sudo tcpdump -i ${my_interface} -w ./traffic/${provider}_aspServer_%Y-%m-%d_%H-%M-%S.pcap "host 172.19.0.3" -W 30 -G 86400 &`



`nohup sudo tcpdump -i ${my_interface} -w ./traffic/${provider}_boaServer_%Y-%m-%d_%H-%M-%S.pcap "host 172.19.0.3" -W 30 -G 86400 &`
