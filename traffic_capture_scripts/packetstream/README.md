
nohup sudo tcpdump -i ${my_interface} -w ./traffic/packetstream_aspServer_%Y-%m-%d_%H-%M-%S.pcap "host 172.19.0.2" -W 30 -G 86400 &


nohup sudo tcpdump -i ${my_interface} -w ./traffic/packetstream_boaServer_%Y-%m-%d_%H-%M-%S.pcap "host 172.19.0.2" -W 30 -G 86400 &
