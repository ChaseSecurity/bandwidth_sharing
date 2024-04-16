import json
from collections import defaultdict
from pprint import pprint
filename = "1.json" #jsonl


maliciousDict = defaultdict(set)
total = set()
with open(filename, 'r') as f:
    for line in f:
        data = json.loads(line)
        domain = data["domain"]
        total.add(domain)
        if "blacklists" in data.keys():
            for key, result in data["blacklists"].items():
                if "not listed" not in result:
                    maliciousDict[key].add(domain)
        # if "urls" in data.keys():
        #     for report in data["urls"]:
        #         maliciousDict[report["threat"]].add(domain)
        
pprint(maliciousDict)
print("total",len(total))
