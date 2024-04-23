#!/bin/bash
#daily job to collect proxy ips
function checkError(){
  if [ $? -ne 0 ];then
    echo "error happenend" | mail -s "$subject" -t "$toList"
    exit 1
  fi
}
if [ $# -lt 2 ];then
  echo "Usage: requestLimit resultDir [oneTimeLimit]"
  exit 1
fi
startTime=$(date +"%s")
scriptDir=/home/ubuntu/clients/
currDate=$(date +"%Y%m%d")
serverName="unconfigued"
if [ -e $scriptDir/serverTag ];then
    serverName=$(cat $scriptDir/serverTag)
fi
subject="ProxyIPCollect_${currDate}_On_$serverName"
#toList="xmi@iu.edu,mixianghang@outlook.com"
toList="xingqitian6@gmail.com,mixianghang@outlook.com"
echo "current date is $currDate"
requestLimit=$1
resultBaseDir=$2
oneTimeLimit=5000
if [ $# -ge 3 ];then
  oneTimeLimit=$3
fi
resultDir=$resultBaseDir/$currDate
mkdir -p $resultDir
currLimit=0
echo "resultDir $resultDir requestLimit $requestLimit , oneTimeLimit $oneTimeLimit"
while [ $currLimit -lt $requestLimit ];
do
  tempTime=$(date +"%s")
  timeCost=$(($tempTime - $startTime))
  if [ $timeCost -ge 86400 ];then
      break
  fi
  echo "currrent limit is $currLimit"
  currStartTime=$(date +"%s")
  python $scriptDir/collectProxyNodes.py $oneTimeLimit $resultDir -tn 20 2>&1 | tee -a $resultDir/stdout.txt
  checkError
  currEndTime=$(date +"%s")
  echo "time cost is $(($currEndTime - $currStartTime)) seconds, currLimit is $currLimit"
  currLimit=$(($currLimit + $oneTimeLimit))
done
responseNum=$(wc -l <$resultDir/resultFile)
uniqIPNum=$(sort -u $resultDir/uniqIPFile | wc -l)
endTime=$(date +"%s")
timeCost=$(($endTime - $startTime))
echo "got $responseNum responses and $uniqIPNum uniq ips with time cost $timeCost seconds" | mail -s "$subject" -t "$toList"
