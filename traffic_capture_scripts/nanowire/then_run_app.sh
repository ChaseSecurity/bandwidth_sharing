docker stop nanowireClient; docker rm nanowireClient; docker run --name nanowireClient --net my_network --ip ${1} --dns 8.8.8.8 zestt/my_nanowire
