import requests
import json
import sys
import os

PATH = os.getcwd() + "/"
version = float(str(sys.version_info[0]) + "." + str(sys.version_info[1]))

if(version < 3.5):
    raise Exception("This script requires Python 3.5+")

with open(PATH + "config.json") as config_file:
    config = json.loads(config_file.read())


def getIPs():
    a = requests.get("https://api.ipify.org?format=json").json().get("ip")
    aaaa = requests.get("https://api6.ipify.org?format=json").json().get("ip")
    ips = []

    if(a.find(".") > -1):
        ips.append({
            "type": "A",
            "ip": a
        })

    if(aaaa.find(":") > -1):
        ips.append({
            "type": "AAAA",
            "ip": aaaa
        })

    return ips


def commitRecord(ip):
    stale_record_ids = []
    for c in config["cloudflare"]:
        subdomains = c["subdomains"]
        response = cf_api("zones/" + c['zone_id'], "GET", c)
        base_domain_name = response["result"]["name"]
        for subdomain in subdomains:
            exists = False
            record = {
                "type": ip["type"],
                "name": subdomain,
                "content": ip["ip"],
                "proxied": c["proxied"]
            }
            list = cf_api(
                "zones/" + c['zone_id'] + "/dns_records?per_page=100&type=" + ip["type"], "GET", c)
            
            full_subdomain = base_domain_name
            if subdomain:
                full_subdomain = subdomain + "." + full_subdomain
            
            dns_id = ""
            for r in list["result"]:
                if (r["name"] == full_subdomain):
                    exists = True
                    if (r["content"] != ip["ip"]):
                        if (dns_id == ""):
                            dns_id = r["id"]
                        else:
                            stale_record_ids.append(r["id"])
            if(exists == False):
                print("Adding new record " + str(record))
                response = cf_api(
                    "zones/" + c['zone_id'] + "/dns_records", "POST", c, {}, record)
            elif(dns_id != ""):
                # Only update if the record content is different
                print("Updating record " + str(record))
                response = cf_api(
                    "zones/" + c['zone_id'] + "/dns_records/" + dns_id, "PUT", c, {}, record)

    # Delete duplicate, stale records
    for identifier in stale_record_ids:
        print("Deleting stale record " + str(identifier))
        response = cf_api(
            "zones/" + c['zone_id'] + "/dns_records/" + identifier, "DELETE", c)

    return True


def cf_api(endpoint, method, config, headers={}, data=False):
    headers = {
        "X-Auth-Email": config['account_email'],
        "X-Auth-Key": config['api_key'],
        **headers
    }

    if(data == False):
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
    else:
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers, json=data)

    return response.json()


for ip in getIPs():
    print("Checking " + ip["type"] + " records")
    commitRecord(ip)
