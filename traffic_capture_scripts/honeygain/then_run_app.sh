# USAGE: ./then_run_app.sh [IP]
# run a container named "psclient1" with assigned ip
# you should use your own [CID]
docker stop hgclient1; docker rm hgclient1;
docker run honeygain/honeygain -tou-get
docker run -d --restart=always --name hgclient1 --net my_network --ip ${1} --dns 8.8.8.8 honeygain/honeygain -tou-accept -email heyyjayden@gmail.com -pass 687195ZDF -device asp1 
