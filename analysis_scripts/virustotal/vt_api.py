# define vt functions
import base64
import json
import logging
import requests
import time
import typing

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logging.info("inited")


SUPPORTED_VT_TYPES = {
    "urls",
    "domains",
}

def get_vt_report(url, api_key, vt_type="urls"):
    if vt_type == "urls":
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    elif vt_type == "domains":
        url_id = url
    base_url = "https://www.virustotal.com/api/v3/{1}/{0}".format(url_id, vt_type)
    header = {"X-Apikey": api_key}
    r = requests.get(base_url, headers = header)

    return r.json()

def get_vt_relationship(
    obj_id,
    api_key,
    rs_name,
    cname, 
    limit=40,
    cursor=None,
    simple=False,
):
    if simple:
        base_url = f"https://www.virustotal.com/api/v3/{cname}/{obj_id}/relationships/{rs_name}"
    else:
        base_url = f"https://www.virustotal.com/api/v3/{cname}/{obj_id}/{rs_name}"
    header = {"X-Apikey": api_key}
    params = {
        "limit": limit,
    }
    if cursor:
        params.update({
            "cursor": cursor,
        })
    r = requests.get(base_url, headers=header, params=params)
    if (r.status_code != 200):
        logging.warning("non-200 vt response: %d", r.status_code)
        return r.json()
    return r.json()

def get_subdomains(
    domain: str,
    api_key: str,
    limit: int=40,
)-> typing.Set[str]:
    result_subdomains = set()
    cursor = None
    while True:
        if len(result_subdomains) >= limit:
            break
        batch_resp = get_vt_relationship(
            domain,
            api_key,
            rs_name="subdomains",
            cname="domains",
            simple=True,
            cursor=cursor,
        )
        # print(batch_resp)
        if is_vt_error(batch_resp):
            logging.warning("Got vt error: %s", batch_resp)
            break
        domain_subset = {
            item["id"]
            for item in batch_resp["data"]
        }
        cursor = batch_resp["meta"].get("cursor", None)
        if domain_subset.issubset(result_subdomains):
            break
        else:
            result_subdomains |= domain_subset
        # denote there is no more page to crawl
        if cursor is None:
            break
    logging.info(f"Got {len(result_subdomains)} subdomains for {domain}")
    return result_subdomains

def get_vt_report_in_batch(
    entities: typing.Set[str],
    api_keys: typing.List[str],
    result_file: str,
    vt_type="urls",
) ->None:
    if vt_type not in SUPPORTED_VT_TYPES:
        raise Exception(f"unsupported vt type: {vt_type}")
    entity_set_queried = set()
    clean_vt_reports = []
    error_vt_count = 0
    invalid_vt_count = 0
    with open(result_file) as f:
        for line in f:
            info = json.loads(line.strip())
            if (
                is_vt_error(info)
                and not is_vt_invalid_arg(info)
                and not is_vt_not_found(info)
            ):
                error_vt_count += 1
                continue
            elif is_vt_invalid_arg(info):
                invalid_vt_count += 1
            clean_vt_reports.append(info)
            if "raw_url" in info:
                entity = info["raw_url"]
            else:
                entity = info["key"]
            entity_set_queried.add(entity)
    logging.info(
        "%d errors and %d invalid args found in previous vt reports",
        error_vt_count,
        invalid_vt_count,
    )
    # overwrite with clean results
    if error_vt_count > 0:
        with open(result_file, "w") as fd:
            for vt_report in clean_vt_reports:
                fd.write(json.dumps(vt_report) + "\n")
    entity_set_to_query = entities - entity_set_queried
    logging.info(
        "%d entities queried, %d left",
        len(entity_set_queried),
        len(entity_set_to_query),
    )
    entity_index = 0
    api_key_index = 0
    entity_list_to_query = list(entity_set_to_query)
    api_key = api_keys[api_key_index]
    query_progress = 0
    with open(result_file, 'a') as f:
        while entity_index < len(entity_list_to_query):
            entity = entity_list_to_query[entity_index]
            try:
                results = get_vt_report(entity, vt_type=vt_type, api_key=api_key)
            except Exception as e:
                logging.warning(f"Got an exception {e}, thus, sleep 60 seconds before resuming")
                time.sleep(60)
                continue
            results['key'] = entity
            if is_vt_not_found(results):
                pass
            elif is_vt_invalid_arg(results):
                logging.warning("vt error: %s", results)
            elif is_vt_error(results):
                logging.error("vt error: %s", results)
                if api_key_index >= len(api_keys) - 1:
                    break
                else:
                    # move to next api key
                    api_key_index += 1
                    api_key = api_keys[api_key_index]
                    continue
            #if ('data' in results):
            f.write(json.dumps(results)+'\n')
            query_progress += 1
            entity_index += 1
            if query_progress % 10 == 0:
                logging.info("Queried VT for %d times", query_progress)
            time.sleep(1)



def is_vt_not_found(vt_json):
    return "error" in vt_json and vt_json["error"]["code"] == "NotFoundError"

def is_vt_error(vt_json):
    return "error" in vt_json

def is_vt_invalid_arg(vt_json):
    return "error" in vt_json and vt_json["error"]["code"] == "InvalidArgumentError"


def main():
    api_key='Anonymize'
    domains=open('domains.txt','r')
    file=open('oout.json','w')
    for line in domains.readlines():
        line=line.strip()
        json_response=get_vt_report(line,api_key,'domains')
        # print(rj)
        file.write(json.dumps(json_response)+'\n')

        logging.info(line + ' RT is ok')



if __name__ == "__main__":
    main()