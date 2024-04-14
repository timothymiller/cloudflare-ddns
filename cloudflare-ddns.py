#!/usr/bin/env python3
#   cloudflare-ddns.py
#   Summary: Access your home network remotely via a custom domain name without a static IP!
#   Description: Access your home network remotely via a custom domain
#                Access your home network remotely via a custom domain
#                A small, 🕵️ privacy centric, and ⚡
#                lightning fast multi-architecture Docker image for self hosting projects.

__version__ = "1.0.2"

import json
import os
import signal
import sys
import threading
import time
import requests
import logging

CONFIG_PATH = os.environ.get('CONFIG_PATH', os.getcwd())
FORMATTER = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")

def getLogger():
    logger = logging.getLogger(__name__)
    return logger

class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        getLogger().info("🛑 Stopping main thread...")
        self.kill_now.set()


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
            getLogger().info("🗑️ Deleted stale record " + identifier)


def getIPs():
    a = None
    aaaa = None
    global ipv4_enabled
    global ipv6_enabled
    global purgeUnknownRecords
    global timeout
    if ipv4_enabled:
        try:
            session = requests.Session()
            session.trust_env = False
            a = session.get(
                "https://1.1.1.1/cdn-cgi/trace", timeout=timeout).text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                getLogger().info("🧩 IPv4 not detected via 1.1.1.1, trying 1.0.0.1")
            # Try secondary IP check
            try:
                session = requests.Session()
                session.trust_env = False
                a = session.get(
                    "https://1.0.0.1/cdn-cgi/trace", timeout=timeout).text.split("\n")
                a.pop()
                a = dict(s.split("=") for s in a)["ip"]
            except Exception:
                global shown_ipv4_warning_secondary
                if not shown_ipv4_warning_secondary:
                    shown_ipv4_warning_secondary = True
                    getLogger().info("🧩 IPv4 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
                if purgeUnknownRecords:
                    deleteEntries("A")
    if ipv6_enabled:
        try:
            session = requests.Session()
            session.trust_env = False
            aaaa = session.get(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace", timeout=timeout).text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                getLogger().info("🧩 IPv6 not detected via 1.1.1.1, trying 1.0.0.1")
            try:
                session = requests.Session()
                session.trust_env = False
                aaaa = session.get(
                    "https://[2606:4700:4700::1001]/cdn-cgi/trace", timeout=timeout).text.split("\n")
                aaaa.pop()
                aaaa = dict(s.split("=") for s in aaaa)["ip"]
            except Exception as e:
                getLogger().info(str(e))
                global shown_ipv6_warning_secondary
                if not shown_ipv6_warning_secondary:
                    shown_ipv6_warning_secondary = True
                    getLogger().info("🧩 IPv6 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
                if purgeUnknownRecords:
                    deleteEntries("AAAA")
    ips = {}
    if (a is not None):
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if (aaaa is not None):
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
                    getLogger().info("📡 Updating record " + str(record))
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "PUT", option, {}, record)
            else:
                getLogger().info("➕ Adding new record " + str(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
            if purgeUnknownRecords:
                for identifier in duplicate_ids:
                    identifier = str(identifier)
                    getLogger().info("🗑️ Deleting stale record " + identifier)
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "DELETE", option)
    getLogger().debug("📡 Updated ip " + str(ip))
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
        session = requests.Session()
        session.trust_env = False
        if (data == False):
            response = session.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers, timeout=timeout)
        else:
            response = session.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint,
                headers=headers, json=data, timeout=timeout)

        if response.ok:
            return response.json()
        else:
            getLogger().info("😡 Error sending '" + method +
                  "' request to '" + response.url + "':")
            getLogger().info(response.text)
            return None
    except Exception as e:
        getLogger().info("😡 An exception occurred while sending '" +
              method + "' request to '" + endpoint + "': " + str(e))
        return None


def updateIPs(ips):
    for ip in ips.values():
        commitRecord(ip)
        #updateLoadBalancer(ip)


if __name__ == '__main__':
    shown_ipv4_warning = False
    shown_ipv4_warning_secondary = False
    shown_ipv6_warning = False
    shown_ipv6_warning_secondary = False
    ipv4_enabled = True
    ipv6_enabled = True
    purgeUnknownRecords = False
    timeout = 15
    logging_level = 'INFO'
    logger = getLogger()
    logging_handler = logging.StreamHandler(sys.stdout)
    logging_handler.setFormatter(FORMATTER)
    logger.addHandler(logging_handler)
    logger.setLevel(logging.getLevelName(logging_level))

    if sys.version_info < (3, 5):
        raise Exception("🐍 This script requires Python 3.5+")

    config = None
    try:
        with open(os.path.join(CONFIG_PATH, "config.json")) as config_file:
            config = json.loads(config_file.read())
    except:
        print("😡 Error reading config.json")
        # wait 10 seconds to prevent excessive logging on docker auto restart
        time.sleep(10)

    if config is not None:
        try:
            logging_level = config["logging"]
            logger.setLevel(logging.getLevelName(logging_level))
        except:
            getLogger().info("⚙️ Error config logger - defaulting to INFO")
            logger.setLevel(logging.INFO)
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            getLogger().info("⚙️ Individually disable IPv4 or IPv6 with new config.json options. Read more about it here: https://github.com/timothymiller/cloudflare-ddns/blob/master/README.md")
        try:
            purgeUnknownRecords = config["purgeUnknownRecords"]
        except:
            purgeUnknownRecords = False
            getLogger().info("⚙️ No config detected for 'purgeUnknownRecords' - defaulting to False")
        try:
            ttl = int(config["ttl"])
        except:
            ttl = 300  # default Cloudflare TTL
            getLogger().info("⚙️ No config detected for 'ttl' - defaulting to 300 seconds (5 minutes)")
        if ttl < 30:
            ttl = 1  #
            getLogger().info("⚙️ TTL is too low - defaulting to 1 (auto)")
        try:
            timeout = int(config["timeout"])
        except:
            timeout = ttl
            getLogger().info("⚙️ No config detected for 'timeout' - defaulting to %d seconds", timeout)
        if timeout < 10:
            timeout = 10
            getLogger().info("⚙️ Timeout is too low - defaulting to %d seconds", timeout)
        if (len(sys.argv) > 1):
            if (sys.argv[1] == "--repeat"):
                if ipv4_enabled and ipv6_enabled:
                    getLogger().info("🕰️ Updating IPv4 (A) & IPv6 (AAAA) records every " + str(ttl) + " seconds")
                elif ipv4_enabled and not ipv6_enabled:
                    getLogger().info("🕰️ Updating IPv4 (A) records every " +
                          str(ttl) + " seconds")
                elif ipv6_enabled and not ipv4_enabled:
                    getLogger().info("🕰️ Updating IPv6 (AAAA) records every " +
                          str(ttl) + " seconds")
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = None
                while True:
                    updateIPs(getIPs())
                    if killer.kill_now.wait(ttl):
                        break
            else:
                getLogger().info("❓ Unrecognized parameter '" +
                      sys.argv[1] + "'. Stopping now.")
        else:
            updateIPs(getIPs())
