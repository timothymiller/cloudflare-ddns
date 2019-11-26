# :rocket: Cloudflare DDNS

Dynamic DNS service based on Cloudflare! Access your home network remotely via a custom domain name without a static IP!

## :us: Origin

This script was written for the Raspberry Pi platform to enable low cost, simple self hosting to promote a more decentralized internet. On execution, the script fetches public IPv4 and IPv6 addresses and creates/updates DNS records for the subdomains in Cloudflare. Stale, duplicate DNS records are removed for housekeeping.

## :vertical_traffic_light: Getting Started

Edit config.json and replace the values with your own.

Values explained:

```json
"api_key": "Your cloudflare API Key",
"account_email": "The email address you use to sign in to cloudflare",
"zone_id": "The ID of the zone that will get the records. From your dashboard click into the zone. Under the overview tab, scroll down and the zone ID is listed in the right rail",
"subdomains": "Array of subdomains you want to update the A & where applicable, AAAA records. IMPORTANT! Only write subdomain name. Do not include the base domain name. (e.g. foo or an empty string to update the base domain)",
"proxied": false (defaults to false. Make it true if you want CDN/SSL benefits from cloudflare. This usually disables SSH)
```

## :fax: Hosting multiple domains on the same IP?
You can save yourself some trouble when hosting multiple domains pointing to the same IP address (in the case of Traefik) by defining one A & AAAA record  'ddns.example.com' pointing to the IP of the server that will be updated by this DDNS script. For each subdomain, create a CNAME record pointing to 'ddns.example.com'. Now you don't have to manually modify the script config every time you add a new subdomain to your site!

## :running: Running

This script requires Python 3.5+, which comes preinstalled on the latest version of Raspbian. Download/clone this repo and execute `./sync`, which will set up a virtualenv, pull in any dependencies, and fire the script.

## :alarm_clock: Scheduling

This script was written with the intention of cron managing it.

## :penguin: Linux instructions (all distros)

1. Upload the cloudflare-ddns folder to your home directory /home/your_username_here/

2. Run the following code in terminal

```bash
crontab -e
```

3. Add the following lines to sync your DNS records every 15 minutes

```bash
*/15 * * * * /home/your_username_here/cloudflare-ddns/sync
```

## License

This Template is licensed under the GNU General Public License, version 3 (GPLv3) and is distributed free of charge.

## Author

Timothy Miller

GitHub: https://github.com/timothymiller 💡

Website: https://timknowsbest.com 💻

Donation: https://timknowsbest.com/donate 💸
