import pickle


def load_pickle_to_set(filename):
    with open(filename, 'rb') as handle:
        loaded_set = pickle.load(handle)
    return loaded_set

vt_mal_ips = load_pickle_to_set('vt_malicious_ips.pkl')
ibm_mal_ips = load_pickle_to_set('ibm_mal_ips.pkl')

count = 0
for ip in vt_mal_ips:
    if ip not in ibm_mal_ips:
        count += 1
print(f"{count} malicious ips in vt_mal_ips are not in ibm_mal_ips")
print(f"ibm_mal_ips has {len(ibm_mal_ips)} malicious ips.")

#========
vt_mal_domains = load_pickle_to_set("vt_malicious_domains.pkl")
ibm_mal_domains = load_pickle_to_set("ibm_mal_domains.pkl")
malDomainsBeyondIbm = set()
for domain in vt_mal_domains:
    if domain not in ibm_mal_domains:
        malDomainsBeyondIbm.add(domain)
        
print(f"{len(malDomainsBeyondIbm)} mal domains in vt are not in ibm")
print(f"ibm_mal_domains has {len(ibm_mal_domains)} mal domains")
        
