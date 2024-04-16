import requests
import os, sys, json
import logging
import time


def example_get_virustotal():
    url = "https://www.virustotal.com/api/v3/files/Anonymize"

    headers = {
        "accept":
        "application/json",
        "x-apikey":
        "Anonymize"
    }

    response = requests.get(url, headers=headers)

    print(response.text)


def get_file_report(file_sha256, api_key):
    baseUrl = "https://www.virustotal.com/api/v3/files/{file}".format(
        file=file_sha256)
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }
    response = requests.get(
        baseUrl,
        headers=headers,
    )
    if response.status_code != 200:
        logging.warning(
            "get non-200 resposne with msg: %d, %s, %s",
            response.status_code,
            response.text,
            file_sha256,
        )
        return 0
    else:
        return response.text


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    src_file = sys.argv[1]
    result_file = sys.argv[2]
    no_get_file = sys.argv[3]
    api_key = sys.argv[4]
    file_sha256_dict = {}
    no_response_file = {}
    logging.info("ok")
    with open(src_file, "r") as fd:
        for line in fd:
            jsonline = json.loads(line.strip())
            file_sha256_dict[jsonline["filepath"]] = jsonline["sha256"]
    logging.info("there are {} files need to query".format(
        len(file_sha256_dict)))
    with open(result_file, "w+") as fd:
        for filepath in file_sha256_dict:
            response = get_file_report(file_sha256_dict[filepath], api_key)
            if response == 0:
                logging.info("not ok")
                no_response_file[filepath] = file_sha256_dict[filepath]
            else:
                dump_dict = {
                    "sha256": file_sha256_dict[filepath],
                    "report": response,
                }
                fd.write(json.dumps(dump_dict) + "\n")
            time.sleep(15)
    logging.info("not get response files are {} nums".format(
        len(no_response_file)))
    with open(no_get_file, "w+") as fd:
        for filepath in no_response_file:
            dump_dict = {
                "filepath": filepath,
                "sha256": no_response_file[filepath],
            }
            fd.write(json.dumps(dump_dict)+"\n")
           