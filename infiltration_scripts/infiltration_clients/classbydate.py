#/usr/bin/env python
import os
import datetime
import time
import json
'''
split the large JSON files by date, and save the rest to left.json
'''
# new file path, i days ago
def get_newfile(i):
    d = str((datetime.datetime.utcnow() - datetime.timedelta(days=i)).date()).split("-")
    filename = d[0] + d[1] + d[2] + '.json'
    aimPath = '/data2/bs/classbydate'   # change
    isExists=os.path.exists(aimPath)
    if not isExists:
        os.makedirs(aimPath)
    result_file = os.path.join(
            aimPath,
            filename,
        )
    return result_file, d

file, d = get_newfile(1)
new_file = open(file, 'a')
origin_file = open('/data2/bs/infiltration_results.json', 'r')   # change
left = open('/data2/bs/left.json', 'a')   # change

for line in origin_file:
    line1 = json.loads(line)
    d1 = json.loads(line1['responseHeader'])
    date = d1['Date'][:16]
    # print(date)
    t = time.strptime(date, '%a, %d %b %Y')
    # print('t', t)
    if t.tm_year==int(d[0]) and t.tm_mon==int(d[1]) and t.tm_mday==int(d[2]):
        new_file.write(line)
        new_file.flush()
    else:
        left.write(line)
        left.flush()

origin_file.close()
new_file.close()
left.close()
os.remove('/data2/bs/infiltration_results.json')   # change
os.rename('/data2/bs/left.json','/data2/bs/infiltration_results.json')
print('finished')
