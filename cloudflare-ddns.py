#!/usr/bin/env python3
#   cloudflare-ddns.py
#   Summary: Access your home network remotely via a custom domain name without a static IP!
#   Description: Access your home network remotely via a custom domain
#                Access your home network remotely via a custom domain
#                A small, 🕵️ privacy centric, and ⚡
#                lightning fast multi-architecture Docker image for self hosting projects.

__version__ = "1.0.4"

from string import Template
from collections import Counter

import ipaddress
import json
import os
import signal
import sys
import threading
import time
import requests

CONFIG_PATH = os.environ.get('CONFIG_PATH', os.getcwd())
# Read in all environment variables that have the correct prefix
ENV_VARS = {key: value for (key, value) in os.environ.items() if key.startswith('CF_DDNS_')}

IPV4_ENDPOINTS = [
    {"url": "https://1.1.1.1/cdn-cgi/trace", "type": "trace"},
    {"url": "https://1.0.0.1/cdn-cgi/trace", "type": "trace"},
    {"url": "https://api.ipify.org", "type": "plain"},
    {"url": "https://ipv4.icanhazip.com", "type": "plain"},
    {"url": "https://ipv4.seeip.org", "type": "plain"},
]

IPV6_ENDPOINTS = [
    {"url": "https://[2606:4700:4700::1111]/cdn-cgi/trace", "type": "trace"},
    {"url": "https://[2606:4700:4700::1001]/cdn-cgi/trace", "type": "trace"},
    {"url": "https://api6.ipify.org", "type": "plain"},
    {"url": "https://ipv6.icanhazip.com", "type": "plain"},
    {"url": "https://ipv6.seeip.org", "type": "plain"},
]

CONSENSUS_THRESHOLD = 3


class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        print("🛑 Stopping main thread...")
        self.kill_now.set()


def get_cloudflare_ips():
    try:
        response = requests.get("https://api.cloudflare.com/client/v4/ips")
        if response.ok:
            data = response.json()
            return {
                "ipv4": data["result"].get("ipv4_cidrs", []),
                "ipv6": data["result"].get("ipv6_cidrs", [])
            }
        else:
            print("⚠️ Could not fetch Cloudflare IP ranges, CF IP validation will be skipped")
            return {"ipv4": [], "ipv6": []}
    except Exception as e:
        print("⚠️ Exception fetching Cloudflare IP ranges: " + str(e) + ", CF IP validation will be skipped")
        return {"ipv4": [], "ipv6": []}


def is_cloudflare_ip(ip, cf_ranges):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(r) for r in cf_ranges)
    except ValueError:
        return False


def fetch_ip_from_endpoint(endpoint):
    try:
        response = requests.get(endpoint["url"], timeout=5)
        if not response.ok:
            return None
        if endpoint["type"] == "trace":
            lines = response.text.strip().split("\n")
            data = dict(s.split("=") for s in lines if "=" in s)
            return data.get("ip")
        else:
            return response.text.strip()
    except Exception:
        return None


def get_consensus_ip(endpoints, cf_ranges, version_label):
    results = []
    for endpoint in endpoints:
        ip = fetch_ip_from_endpoint(endpoint)
        if ip is None:
            continue
        if is_cloudflare_ip(ip, cf_ranges):
            print("⚠️ " + endpoint["url"] + " returned a Cloudflare IP (" + ip + "), ignoring")
            continue
        results.append(ip)

    if not results:
        print("⚠️ No valid " + version_label + " addresses detected from any endpoint, skipping update")
        return None

    counts = Counter(results)
    most_common_ip, count = counts.most_common(1)[0]

    if count >= CONSENSUS_THRESHOLD:
        print("✅ " + version_label + " consensus reached: " + most_common_ip + " (" + str(count) + "/" + str(len(results)) + " sources agree)")
        return most_common_ip
    else:
        print("⚠️ No " + version_label + " consensus reached (threshold: " + str(CONSENSUS_THRESHOLD) + ", best: " + most_common_ip + " with " + str(count) + "/" + str(len(results)) + " sources), skipping update")
        return None


def deleteEntries(type):
    # Helper function for deleting A or AAAA records
    # in the case of no IPv4 or IPv6 connection, yet
    # existing A or AAAA records are found.
    for option in config["cloudflare"]:
        answer = cf_api(
            "zones/" + option['zone_id'] +
            "/dns_records?per_page=100&type=" + type,
            "GET", option)
        if answer is None or answer["result"] is None:
            time.sleep(5)
            return
        for record in answer["result"]:
            identifier = str(record["id"])
            cf_api(
                "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                "DELETE", option)
            print("🗑️ Deleted stale record " + identifier)


def getIPs():
    global ipv4_enabled
    global ipv6_enabled
    global purgeUnknownRecords

    cf_ranges = get_cloudflare_ips()

    a = None
    aaaa = None

    if ipv4_enabled:
        a = get_consensus_ip(IPV4_ENDPOINTS, cf_ranges["ipv4"], "IPv4")
        if a is None and purgeUnknownRecords:
            deleteEntries("A")

    if ipv6_enabled:
        aaaa = get_consensus_ip(IPV6_ENDPOINTS, cf_ranges["ipv6"], "IPv6")
        if aaaa is None and purgeUnknownRecords:
            deleteEntries("AAAA")

    ips = {}
    if a is not None:
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if aaaa is not None:
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    return ips


def commitRecord(ip):
    global ttl
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            time.sleep(5)
            return
        base_domain_name = response["result"]["name"]
        for subdomain in subdomains:
            try:
                name = subdomain["name"].lower().strip()
                proxied = subdomain["proxied"]
            except:
                name = subdomain
                proxied = option["proxied"]
            fqdn = base_domain_name
            # Check if name provided is a reference to the root domain
            if name != '' and name != '@':
                fqdn = name + "." + base_domain_name
            record = {
                "type": ip["type"],
                "name": fqdn,
                "content": ip["ip"],
                "proxied": proxied,
                "ttl": ttl
            }
            dns_records = cf_api(
                "zones/" + option['zone_id'] +
                "/dns_records?per_page=100&type=" + ip["type"],
                "GET", option)
            identifier = None
            modified = False
            duplicate_ids = []
            if dns_records is not None:
                for r in dns_records["result"]:
                    if (r["name"] == fqdn):
                        if identifier:
                            if r["content"] == ip["ip"]:
                                duplicate_ids.append(identifier)
                                identifier = r["id"]
                            else:
                                duplicate_ids.append(r["id"])
                        else:
                            identifier = r["id"]
                            if r['content'] != record['content'] or r['proxied'] != record['proxied']:
                                modified = True
            if identifier:
                if modified:
                    print("📡 Updating record " + str(record))
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "PUT", option, {}, record)
                else:
                    print("✅ Record already up to date: " + fqdn + " -> " + ip["ip"])
            else:
                print("➕ Adding new record " + str(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
            if purgeUnknownRecords:
                for identifier in duplicate_ids:
                    identifier = str(identifier)
                    print("🗑️ Deleting stale record " + identifier)
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "DELETE", option)
    return True


def updateLoadBalancer(ip):

    for option in config["load_balancer"]:
        pools = cf_api('user/load_balancers/pools', 'GET', option)

        if pools:
            idxr = dict((p['id'], i) for i, p in enumerate(pools['result']))
            idx = idxr.get(option['pool_id'])

            origins = pools['result'][idx]['origins']

            idxr = dict((o['name'], i) for i, o in enumerate(origins))
            idx = idxr.get(option['origin'])

            origins[idx]['address'] = ip['ip']
            data = {'origins': origins}

            response = cf_api(f'user/load_balancers/pools/{option["pool_id"]}', 'PATCH', option, {}, data)


def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token, **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],
        }
    try:
        if (data == False):
            response = requests.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
        else:
            response = requests.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint,
                headers=headers, json=data)

        if response.ok:
            return response.json()
        else:
            print("😡 Error sending '" + method +
                  "' request to '" + response.url + "':")
            print(response.text)
            return None
    except Exception as e:
        print("😡 An exception occurred while sending '" +
              method + "' request to '" + endpoint + "': " + str(e))
        return None


def updateIPs(ips):
    for ip in ips.values():
        commitRecord(ip)
        #updateLoadBalancer(ip)


if __name__ == '__main__':
    ipv4_enabled = True
    ipv6_enabled = True
    purgeUnknownRecords = False

    if sys.version_info < (3, 5):
        raise Exception("🐍 This script requires Python 3.5+")

    config = None
    try:
        with open(os.path.join(CONFIG_PATH, "config.json")) as config_file:
            if len(ENV_VARS) != 0:
                config = json.loads(Template(config_file.read()).safe_substitute(ENV_VARS))
            else:
                config = json.loads(config_file.read())
    except:
        print("😡 Error reading config.json")
        # wait 10 seconds to prevent excessive logging on docker auto restart
        time.sleep(10)

    if config is not None:
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            print("⚙️ Individually disable IPv4 or IPv6 with new config.json options. Read more about it here: https://github.com/timothymiller/cloudflare-ddns/blob/master/README.md")
        try:
            purgeUnknownRecords = config["purgeUnknownRecords"]
        except:
            purgeUnknownRecords = False
            print("⚙️ No config detected for 'purgeUnknownRecords' - defaulting to False")
        try:
            ttl = int(config["ttl"])
        except:
            ttl = 300  # default Cloudflare TTL
            print(
                "⚙️ No config detected for 'ttl' - defaulting to 300 seconds (5 minutes)")
        if ttl < 30:
            ttl = 1  #
            print("⚙️ TTL is too low - defaulting to 1 (auto)")
        if (len(sys.argv) > 1):
            if (sys.argv[1] == "--repeat"):
                if ipv4_enabled and ipv6_enabled:
                    print(
                        "🕰️ Updating IPv4 (A) & IPv6 (AAAA) records every " + str(ttl) + " seconds")
                elif ipv4_enabled and not ipv6_enabled:
                    print("🕰️ Updating IPv4 (A) records every " +
                          str(ttl) + " seconds")
                elif ipv6_enabled and not ipv4_enabled:
                    print("🕰️ Updating IPv6 (AAAA) records every " +
                          str(ttl) + " seconds")
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = None
                while True:
                    updateIPs(getIPs())
                    if killer.kill_now.wait(ttl):
                        break
            else:
                print("❓ Unrecognized parameter '" +
                      sys.argv[1] + "'. Stopping now.")
        else:
            updateIPs(getIPs())