#/usr/bin/env python
import os
import json

'''
Count the number of IP captured by packetstream every day and the total number of IP captured.
'''

def getfiles():
    filenames=os.listdir(r'/data2/bs/classbydate')
    return filenames

filenames = getfiles()
print(filenames)

dict={}
file = open('/data2/bs/packetstream.json', 'r')
for line in file:
    line1 = json.loads(line)
    dict[line1] = 1

dict_y={}
file = open('/data2/bs/iproyal.json', 'r') # /data2/bs/iproyal.json
for line in file:
    line1 = json.loads(line)
    dict_y[line1] = 1
file.close()

total = 0
total_y = 0

for file in filenames:
    file1 = open('/data2/bs/classbydate/' + file, 'r')
    for line in file1:
        line1 = json.loads(line)
        proxy = line1["proxies"]
        ip = line1['ip']
        if proxy['http'] == "http://cchow:ZowwdcC1svivu7pK@proxy.packetstream.io:31112":
            total += 1
            if ip not in dict.keys():
                dict[line1['ip']] = 1
        else:
            total_y += 1
            if ip not in dict_y.keys():
                dict_y[line1['ip']] = 1
    print(file, 'finished.')
    file1.close()

print('packetstream total ip number:' ,total)
print('packetstream net ip number:', len(dict))
print('iproyal total ip number:' ,total_y)
print('iproyal net ip number:', len(dict_y))

file = open('/data2/bs/packetstream.json', 'w')
for item in dict:
    jsonString = json.dumps(item)
    file.write(jsonString + '\n')
    file.flush()
file.close()

file = open('/data2/bs/iproyal.json', 'w') # /data2/bs/iproyal.json
for item in dict_y:
    jsonString = json.dumps(item)
    file.write(jsonString + '\n')
    file.flush()
file.close()
