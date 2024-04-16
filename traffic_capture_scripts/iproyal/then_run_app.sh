docker stop iproyalClient; docker rm iproyalClient; docker run -d --name iproyalClient --net my_network --ip ${1} --dns 8.8.8.8 zestt/my_iproyal
