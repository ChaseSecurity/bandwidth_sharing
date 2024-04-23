#!/bin/bash
#domainList=("rpaas.site" "rpaas-china.site" "rpaas-brazil.site" "rpaas-eu.site" "rpaas-india.site" "rpaas-singapore.site" "servicehosting.org" "servicehosting.online" "servicehosting.website")
resultDir=$1
if [ ! -e $resultDir ];then
    mkdir -p $resultDir
fi
domainList=("rpaas-us.site")
for domain in ${domainList[@]};
do
    keyFile=$resultDir/$domain.key
    csrFile=$resultDir/$domain.csr
    openssl req -nodes -newkey rsa:2048 -keyout $keyFile -out $csrFile -subj "/C=US/ST=Illinois/L=Chicago/O=RPaaS/OU=X Department/CN=*.$domain"
done
