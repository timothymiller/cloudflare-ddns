import requests, json, sys, signal, os, time, threading

class GracefulExit:
  def __init__(self):
    self.kill_now = threading.Event()
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)

  def exit_gracefully(self, signum, frame):
    print("🛑 Stopping main thread...")
    self.kill_now.set()

def deleteEntries(type):
    # Helper function for deleting A or AAAA records
    # in the case of no IPv4 or IPv6 connection, yet
    # existing A or AAAA records are found.
    for option in config["cloudflare"]:
        answer = cf_api(
            "zones/" + option['zone_id'] + "/dns_records?per_page=100&type=" + type,
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
    a = None
    aaaa = None
    global ipv4_enabled
    global ipv6_enabled
    if ipv4_enabled:
        try:
            a = requests.get("https://1.1.1.1/cdn-cgi/trace").text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                print("🧩 IPv4 not detected")
            if delete_stale_records:
                deleteEntries("A")
    if ipv6_enabled:
        try:
            aaaa = requests.get("https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                print("🧩 IPv6 not detected")
            if delete_stale_records:
                deleteEntries("AAAA")
    ips = {}
    if(a is not None):
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if(aaaa is not None):
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    print("IPs found: " + str(ips))
    return ips

def commitRecord(ip):
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            time.sleep(5)
            return
        base_domain_name = response["result"]["name"]
        ttl = 300 # default Cloudflare TTL
        for subdomain in subdomains:
            subdomain = subdomain.lower().strip()
            record = {
                "type": ip["type"],
                "name": subdomain,
                "content": ip["ip"],
                "proxied": option["proxied"],
                "ttl": ttl
            }
            dns_records = cf_api(
                "zones/" + option['zone_id'] + "/dns_records?per_page=100&type=" + ip["type"], 
                "GET", option)
            fqdn = base_domain_name
            if subdomain:
                fqdn = subdomain + "." + base_domain_name
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
                                print("Current IP does not match Clouflare IP for subdomain " + str(record["name"]))
                                modified = True
            if identifier:
                if modified:
                    print("📡 Updating record " + str(record))
                    response = cf_api(
                        "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                        "PUT", option, {}, record)
            else:
                print("➕ Adding new record " + str(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
            if delete_stale_records:
                for identifier in duplicate_ids:
                    identifier = str(identifier)
                    print("🗑️ Deleting stale record " + identifier)
                    response = cf_api(
                        "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                        "DELETE", option)
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
            method, "https://api.cloudflare.com/client/v4/" + endpoint,
            headers=headers, json=data)

    if response.ok:
        return response.json()
    else:
        print("📈 Error sending '" + method + "' request to '" + response.url + "':")
        print(response.text)
        return None

def updateIPs(ips):
    for ip in ips.values():
        commitRecord(ip)

def pingHealthchecks(healthchecks_ping_url):
    try:
        requests.get(healthchecks_ping_url, timeout=10)
    except requests.RequestException as e:
        print("Ping to healthchecks failed: %s" % e)

if __name__ == '__main__':
    PATH = os.getcwd() + "/"
    version = float(str(sys.version_info[0]) + "." + str(sys.version_info[1]))
    shown_ipv4_warning = False
    shown_ipv6_warning = False
    ipv4_enabled = True
    ipv6_enabled = True
    delete_stale_records = False

    if(version < 3.5):
        raise Exception("🐍 This script requires Python 3.5+")

    config = None
    try:
        with open(PATH + "config.json") as config_file:
            config = json.loads(config_file.read())
    except:
        print("😡 Error reading config.json")
        time.sleep(60) # wait 60 seconds to prevent excessive logging on docker auto restart

    if config is not None:
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            print("⚙️ Individually disable IPv4 or IPv6 with new config.json options. Read more about it here: https://github.com/timothymiller/cloudflare-ddns/blob/master/README.md")
        try:
            delete_stale_records = config["delete_stale_records"]
        except:
            delete_stale_records = False
            print("⚙️ No config detected for 'delete_stale_records' - default to False")
        try:
            healthchecks_ping_url = config["healthchecks_ping_url"]
        except:
            healthchecks_ping_url = None
            print("⚙️ No config detected for 'healthchecks_ping_url' - default to None")
        if(len(sys.argv) > 1):
            if(sys.argv[1] == "--repeat"):
                updateIPs(getIPs())
                delay = 5*60
                if ipv4_enabled and ipv6_enabled:
                    print("🕰️ Updating IPv4 (A) & IPv6 (AAAA) records every 5 minutes")
                elif ipv4_enabled and not ipv6_enabled:
                    print("🕰️ Updating IPv4 (A) records every 5 minutes")
                elif ipv6_enabled and not ipv4_enabled:
                    print("🕰️ Updating IPv6 (AAAA) records every 5 minutes")
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = None
                while True:
                    if killer.kill_now.wait(delay):
                        break
                    print("Checking for IP changes")
                    updateIPs(getIPs())
                    if healthchecks_ping_url != None:
                        pingHealthchecks(healthchecks_ping_url)
            else:
                print("❓ Unrecognized parameter '" + sys.argv[1] + "'. Stopping now.")
        else:
            updateIPs(getIPs())