# :rocket: Cloudflare DDNS

Dynamic DNS service based on Cloudflare! Access your home network remotely via a custom domain name without a static IP!

## :us: Origin

This script was written for the Raspberry Pi platform to enable low cost, simple self hosting to promote a more decentralized internet. On execution, the script fetches public IPv4 and IPv6 addresses and creates/updates DNS records for the subdomains in Cloudflare. Stale, duplicate DNS records are removed for housekeeping.

## :vertical_traffic_light: Getting Started

First copy the example configuration file into the real one.

```bash
cp config-example.json config.json
```

Edit `config.json` and replace the values with your own.

### Authentication methods

You can choose to use either the newer API tokens, or the traditional API keys

To generate a new API tokens, go to your [Cloudflare Profile](https://dash.cloudflare.com/profile/api-tokens) and create a token capable of **Edit DNS**. Then replace the value in
```json
"authentication":
  "api_token": "Your cloudflare API token, including the capability of **Edit DNS**"
```

Alternatively, you can use the traditional API keys by setting appropriate values for: 
```json
"authentication":
  "api_key":
    "api_key": "Your cloudflare API Key",
    "account_email": "The email address you use to sign in to cloudflare",
```

### Other values explained

```json
"zone_id": "The ID of the zone that will get the records. From your dashboard click into the zone. Under the overview tab, scroll down and the zone ID is listed in the right rail",
"subdomains": "Array of subdomains you want to update the A & where applicable, AAAA records. IMPORTANT! Only write subdomain name. Do not include the base domain name. (e.g. foo or an empty string to update the base domain)",
"proxied": false (defaults to false. Make it true if you want CDN/SSL benefits from cloudflare. This usually disables SSH)
```

## :fax: Hosting multiple domains on the same IP?
You can save yourself some trouble when hosting multiple domains pointing to the same IP address (in the case of Traefik) by defining one A & AAAA record  'ddns.example.com' pointing to the IP of the server that will be updated by this DDNS script. For each subdomain, create a CNAME record pointing to 'ddns.example.com'. Now you don't have to manually modify the script config every time you add a new subdomain to your site!

## :whale: Deploy with Docker Compose

Precompiled images are available via the official docker container [on DockerHub](https://hub.docker.com/r/timothyjmiller/cloudflare-ddns).

Modify the host file path of config.json inside the volumes section of docker-compose.yml.

```yml
version: "3.7"
services:
  cloudflare-ddns:
    image: timothyjmiller/cloudflare-ddns:latest
    container_name: cloudflare-ddns
    security_opt:
      - no-new-privileges:true
    network_mode: "host"
    environment:
      - PUID=1000
      - PGID=1000
    volumes:
      - /YOUR/PATH/HERE/config.json:/config.json
    restart: unless-stopped
```

#### :warning: IPv6
Docker requires network_mode be set to host in order to access the IPv6 public address.

### :running: Running

From the project root directory

```bash
docker-compose up -d
```

## Building from source

Create a config.json file with your production credentials.

Give build-docker-image.sh permission to execute.

```bash
sudo chmod +x ./build-docker-image.sh
```

At project root, run the build-docker-image.sh script.

```bash
./build-docker-image.sh
```

#### Run the locally compiled version

```bash
docker run -d timothyjmiller/cloudflare_ddns:latest
```

## :penguin: (legacy) Linux + cron instructions (all distros)

### :running: Running

This script requires Python 3.5+, which comes preinstalled on the latest version of Raspbian. Download/clone this repo and give permission to the project's bash script by running `chmod +x ./start-sync.sh`. Now you can execute `./start-sync.sh`, which will set up a virtualenv, pull in any dependencies, and fire the script.

1. Upload the cloudflare-ddns folder to your home directory /home/your_username_here/

2. Run the following code in terminal

```bash
crontab -e
```

3. Add the following lines to sync your DNS records every 15 minutes

```bash
*/15 * * * * /home/your_username_here/cloudflare-ddns/start-sync.sh
```

## License

This Template is licensed under the GNU General Public License, version 3 (GPLv3).

## Author

Timothy Miller

[View my GitHub profile 💡](https://github.com/timothymiller)

[View my personal website 💻](https://timknowsbest.com)