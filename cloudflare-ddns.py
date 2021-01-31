import requests, json, sys, signal, os
import time

PATH = os.getcwd() + "/"
version = float(str(sys.version_info[0]) + "." + str(sys.version_info[1]))

if(version < 3.5):
    raise Exception("This script requires Python 3.5+")

def sigtermHandler(sig_no, stack_frame):
    print("Caught SIGTERM, shutting down...")
    sys.exit(0)

signal.signal(signal.SIGTERM, sigtermHandler)

with open(PATH + "config.json") as config_file:
    config = json.loads(config_file.read())

def getIPs():
    a = ""
    aaaa = ""
    try:
        a = requests.get("https://1.1.1.1/cdn-cgi/trace").text.split("\n")
        a.pop()
        a = dict(s.split("=") for s in a)["ip"]
    except Exception:
        print("Warning: IPv4 not detected.")
    try:
        aaaa = requests.get("https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
        aaaa.pop()
        aaaa = dict(s.split("=") for s in aaaa)["ip"]
    except Exception:
        print("Warning: IPv6 not detected.")
    ips = []

    if(a.find(".") > -1):
        ips.append({
            "type": "A",
            "ip": a
        })
    else:
        print("Warning: IPv4 not detected.")

    if(aaaa.find(":") > -1):
        ips.append({
            "type": "AAAA",
            "ip": aaaa
        })
    else:
        print("Warning: IPv6 not detected.")

    return ips


def commitRecord(ip):
    stale_record_ids = []
    for c in config["cloudflare"]:
        subdomains = c["subdomains"]
        response = cf_api("zones/" + c['zone_id'], "GET", c)
        base_domain_name = response["result"]["name"]
        ttl = 120
        if "ttl" in c:
            ttl=c["ttl"]
        for subdomain in subdomains:
            subdomain = subdomain.lower()
            exists = False
            record = {
                "type": ip["type"],
                "name": subdomain,
                "content": ip["ip"],
                "proxied": c["proxied"],
                "ttl": ttl
            }
            list = cf_api(
                "zones/" + c['zone_id'] + "/dns_records?per_page=100&type=" + ip["type"], "GET", c)

            full_subdomain = base_domain_name
            if subdomain:
                full_subdomain = subdomain + "." + full_subdomain

            dns_id = ""
            matches = False
            for r in list["result"]:
                if (r["name"] == full_subdomain):
                    exists = True
                    if (r["content"] != ip["ip"]):
                        if (dns_id == ""):
                            dns_id = r["id"]
                        else:
                            stale_record_ids.append(r["id"])
                    else:
                        matches = True
            if(matches == True):
                print("The %s Record for '%s' is already up to date: %s"
                %(record["type"], record["name"], record["content"]))
            elif(exists == False):
                response = cf_api(
                    "zones/" + c['zone_id'] + "/dns_records", "POST", c, {}, record)
                print("The %s Record for '%s' was just added: %s"
                %(record["type"], record["name"], record["content"]))
            elif(dns_id != ""):
                # Only update if the record content is different
                response = cf_api(
                    "zones/" + c['zone_id'] + "/dns_records/" + dns_id, "PUT", c, {}, record)
                print("The %s Record for '%s' was just updated: %s"
                %(record["type"], record["name"], record["content"]))

    # Delete duplicate, stale records
    for identifier in stale_record_ids:
        print("Deleting stale record " + str(identifier))
        response = cf_api(
            "zones/" + c['zone_id'] + "/dns_records/" + identifier, "DELETE", c)

    return True


def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token,
            **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],
        }

    if(data == False):
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
    else:
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers, json=data)

    return response.json()

def updateIPs():
    for ip in getIPs():
        commitRecord(ip)

try:
    if(len(sys.argv) > 1):
        if(sys.argv[1] == "--repeat"):
            print("Updating A & AAAA records every 10 minutes")
            updateIPs()
            delay = 10*60 # 10 minutes
            next_time = time.time() + delay
            while True:
                time.sleep(max(0, next_time - time.time()))
                updateIPs()
                next_time += (time.time() - next_time) // delay * delay + delay
        else:
            print("Unrecognized parameter '" + sys.argv[1] + "'. Stopping now.")
    else:
        updateIPs()
except SystemExit:
    print("Goodbye!")
