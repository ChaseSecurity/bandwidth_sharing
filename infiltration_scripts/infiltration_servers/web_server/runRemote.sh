#!/bin/bash
if [ $# -lt 1 ];then
    echo 'remoteServer'
    exit 1
fi
remoteServerList=($1)
currDir=$(cd $(dirname $0);pwd)
for remoteServer in ${remoteServerList[@]};
do
    echo $remoteServer
    echo $currDir
    scp -r $currDir $remoteServer:
    ssh -t $remoteServer "cd web_server && ./deploy.sh"
done
