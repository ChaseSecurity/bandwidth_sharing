# Traffic capture
```
networkID=$(docker network create --driver bridge --subnet 172.19.0.0/16 --gateway 172.19.0.1 --dns 8.8.8.8 my_network)
my_interface="br-"${networkID:0:12}
sudo tcpdump -i ${my_interface} -w nanowire_date+%s_%m_%d.pcap "host 172.19.0.5" -W 30 -G 86400 
```
# API
Get your own API following the instructions on: https://nanowire.com/instructions

Bandwidth-sharing selling API key Dongfang's account: `haRCp7JwiTbeOUTPq6y1j7WmDYRwyuM3kjl6oZgO67lTFFAndS`

# Wrap up nanowire exec to docker image
## Download exec based on your platform via official link

https://nanowire.com/instructions

## Build

```
docker build . -t=testnano
```
or: ([dockerAccount]=zestt)
```
docker build --tag=[dockerAccount]/my_nanowire .
```
## Run 
```
docker run --name nanowire1 --net my_network --ip 172.19.0.5 --dns 8.8.8.8 testnano
```
or
```
docker run --name nanowire1 --net my_network --ip 172.19.0.5 --dns 8.8.8.8 [dockerAccount]/my_nanowire
```

## Issues
- certificate error:
  ```
  ERR authentication failed error="rpc error: code = Unavailable desc = connection error: desc = \"transport: authentication handshake failed: x509: certificate signed by unknown authority\"" pid=router
  ```
  - Solution: `apt-get update && apt-get install -y ca-certificates` [Reference1.](https://stackoverflow.com/questions/29319538/issue-with-my-ca-certificates-crt)
