import json



filename = "1.txt"

with open(filename, 'r') as f:
    for line in f:
        data = json.loads(line)
        if data["query_status"] not in ["no_results", "invalid_url"]:
            print(data)
