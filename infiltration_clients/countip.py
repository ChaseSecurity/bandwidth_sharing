#/usr/bin/env python
import os
import json

'''
Count the number of IP captured every day and the total number of IP captured.
'''
def getfiles():
    filenames=os.listdir(r'/data2/bs/classbydate')  # IP files stored by date.
    return filenames

filenames = getfiles()
print(filenames)
dict={}
file2 = open('/data2/bs/list.json', 'r')
for line in file2:
    line1 = json.loads(line)
    dict[line1] = 1
file2.close()
#num = 0
total = 0
# num_file = open('/data2/bs/num_file.json', 'w')  # Count results.

for file in filenames:
    file1 = open('/data2/bs/classbydate/' + file, 'r')
    for line in file1:
        line1 = json.loads(line)
        ip = line1['ip']
        total += 1
        if ip not in dict.keys():
            dict[line1['ip']] = 1
            # num_file.write(json.dumps(ip) + '\n')
            # num_file.flush()
        # print('line1',line1)
    #num = len(list) - num
    #print('dumped', num, 'ip in', file[:8])   # Net increased IP number.
    print(file, 'finished.')
    file1.close()


# print(list)
print('total ip number:' ,total)
print('net ip number:', len(dict))
file2 = open('/data2/bs/list.json', 'w')
for item in dict:
    jsonString = json.dumps(item)
    file2.write(jsonString + '\n')
    file2.flush()
file2.close()
# num_file.write('total ip number:'+str(total)+'\n'+'net ip number:'+str(len(list)))
# num_file.flush()
# num_file.close()
