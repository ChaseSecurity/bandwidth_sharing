- Generate six tuples(protocol, source ip, source port, dst ip, dst port, timestamp) from pcap file:

`tshark -r your.pcap -T fields -e ip.proto -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.time -E header=y -E separator=, -E quote=d -E occurrence=f > your_output.csv`
