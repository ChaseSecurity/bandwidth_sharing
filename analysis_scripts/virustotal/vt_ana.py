import logging
import os, sys
import json
from collections import defaultdict
import pandas as pd

def main():
    name_categorys_domains={}
    name_result_domains={}
    json_file=open('oout.json','r')
    

    for line in json_file.readlines():
        try:
            line=line.strip()
            line=json.loads(line)
            if 'error' in line:
                continue
            data=line['data']
            attributes=data['attributes']
            last_analysis_results=attributes['last_analysis_results']
            domain=data['id']
            for name,arrs in last_analysis_results.items():
                if name not in name_categorys_domains:
                    name_categorys_domains[name]={}
                if name not in name_result_domains:
                    name_result_domains[name]={}

                if arrs['category'] not in name_categorys_domains[name]:
                    name_categorys_domains[name][arrs['category']]=[domain]
                else:
                    name_categorys_domains[name][arrs['category']].append(domain)
                if arrs['result'] not in name_result_domains[name]:
                    name_result_domains[name][arrs['result']]=[domain]
                else:
                    name_result_domains[name][arrs['result']].append(domain)


        except:
            print(line)

    out_txt=open('stat.txt','w')
    for name,categorys_domains in name_categorys_domains.items():
        out_txt.write(name+"\n")
        for categorys,domains in categorys_domains.items():
            out_txt.write("\t"+categorys+"\n")
            for domain in domains:
                out_txt.write("\t\t"+domain+"\n")
        out_txt.write("\n")

    out_json=open('stat.json','w')
    out_stat={}
    out_stat['name_categorys_domains']=name_categorys_domains
    out_stat['name_result_domains']=name_result_domains
    json.dump(out_stat,out_json)
    # print(name_categorys_domains)
    # print(name_result_domains)

if __name__ == "__main__":
    main()