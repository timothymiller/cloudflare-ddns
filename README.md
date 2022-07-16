# Cloudflare DDNS Enhanced

Fork of [Cloudflare DDNS](https://github.com/timothymiller/cloudflare-ddns/) with some modifications and improvements.

Access your home network remotely via a custom domain name without a static IP!

#### \# Here are some improvements:
- More flexibility - for example, you can configure a specific TTL and proxying for each individual (sub)domain. You can also set standard values for each domain zone.
- Support for command line arguments and environment variables
- More detailed and customizable logging
- Some bug fixes

<details>
<summary><b> # (Almost) full list of improvements</b></summary>

#### >> New features:
- Ability to set TTL and proxying values for each (sub)domain (if specified, overwrites the standard value for the zone)
- Ability to set TTL and proxying values for each domain zone
- Repeat mode settings (command line arguments or section in config - whether enabled; delay)
- Support for command line arguments and environment variables (command line arguments: path to config, repeat mode, repeat delay, verbose level, "Docker mode"; environment variables: path to config, "Docker mode")

#### >> Fixes and improvements:
- **Fixed issue** [#91](https://github.com/timothymiller/cloudflare-ddns/issues/91) - The root domain record is no longer updated (CF Error 9000: DNS name is invalid).
- **Fixed issue** [#74](https://github.com/timothymiller/cloudflare-ddns/issues/74) - Script not running with crontab. Thanks to [@Bagus-Septianto](https://github.com/Bagus-Septianto)!
- **Fix:** due to incorrect tabulation in the deleteEntries function did not work correctly. Stale records were deleted only from the last domain zone.
- **Improvement:** when updating subdomains, all subdomains of the zone are now requested only once. In the original v1.0.1 version, for some reason they were requested before updating each subdomain, which slowed down the program quite a lot. Personally, I don't see any reason to request them every time before an update.
- **Improvement:** better exception handling
- **Improvement:** a more "pythonic" style of writing the code; improved readability

</details>

##  How Private & Secure?

1. Uses zero-log external IPv4 & IPv6 provider ([cdn-cgi/trace](https://www.cloudflare.com/cdn-cgi/trace))
2. HTTPS only via Python Software Foundation requests module
3. Open source for open audits
4. Regular updates

## Getting Started

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

## Configuration

### \# Config example

```json
{
  "cloudflare": [
    {
      "authentication": {
          "api_token": "eXampLE-0123456789-LYnXes-are-c0ol-01234"
      },
      "zone_id": "1234567890abcdefghijkl0123456789",
      "subdomains": [
        {"name": "@"},
        {"name": "www"},
        {"name": "files", "ttl": 1500},
        {"name": "secure", "is_proxied": true},
      ],
      "default_is_proxied": false,
      "default_ttl": 300
    }
  ],
  "a": true,
  "aaaa": false,
  "purge_unknown_records": false
}
```

<details>
<summary><b> # Configuration variables</b></summary>

**Note:** There is no need to specify all the listed variables. It is not necessary to specify variables of the type *Optional[...]* in the config. Specify if you only need to change certain settings.

### Main settings
| Variable                 | Type           | Example                                   | Description                                             |
| ------------------------ | -------------- | ----------------------------------------- | ------------------------------------------------------- |
| cloudflare               | List[Dict]     |                                           | Settings for each zone
| a                        | bool           | "a": true                                 | Create A (IPv4) records?
| aaaa                     | bool           | "aaaa": false                             | Create AAAA (IPv6) records?
| purge_unknown_records    | Optional[bool] | "purge_unknown_records": true             | Purge unknown records?
| repeat                   | Optional[Dict] | "repeat": {"enabled": true, "delay": 300} | Repeat mode settings
| logging                  | Optional[Dict] | "logging": {"level": "DEBUG"}             | Logging settings


### Zone settings
| Variable                 | Type           | Example                                                    | Description                                             |
| ------------------------ | -------------- | ---------------------------------------------------------- | ------------------------------------------------------- |
| authentication           | dict           |                                                            | Authentication settings - tokens, mail
| zone_id                  | int            | "zone_id": "1234567890abcdefghijkl0123456789"              | Domain zone ID
| subdomains               | List[Dict]     | "subdomains": [{"name": "@"}, {"name": "sub", "ttl": 600}] | Array with settings for each subdomain you want to update
| default_is_proxied       | Optional[bool] | "default_is_proxied": true                                 | Enable or disable proxying for subdomains default_ttl by default
| default_ttl              | Optional[bool] | "default_ttl": 900                                         | The TTL value that will be set for each subdomain in this zone by default

### Authentication settings
| Variable                 | Type           | Example                                                                  | Description                                             |
| ------------------------ | -------------- | ------------------------------------------------------------------------ | ------------------------------------------------------- |
| api_token                | Optional[str]  | "api_token": "eXampLE-0123456789-LYnXes-are-c0ol-01234"                  | Your cloudflare API token, including the capability of *Edit DNS*. **Note:** The *api_token* has a higher priority than *api_key*.
| api_key                  | Optional[dict] | "api_key": {"account_email": "admin@coolsite.example", "api_key": "..."} | Credentials for your account

### Credentials for your account (api_key section)
| Variable                 | Type           | Example                                               | Description                                             |
| ------------------------ | -------------- | ----------------------------------------------------- | ------------------------------------------------------- |
| account_email            | Optional[str]  | "account_email": "admin@coolsite.example"             | Credentials for your account
| api_key                  | Optional[dict] | "api_key": "eXampLE-0123456789-LYnXes-are-c0ol-01234" | Credentials for your account

### Subdomain settings
| Variable                 | Type           | Example               | Description                                              |
| ------------------------ | -------------- | --------------------- | ------------------------------------------------------- |
| name                     | str            | "name": "ddns"        | Name of subdomain. **IMPORTANT! Only write subdomain name.** Do not include the [FDQN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name). If you also need to update the root record, specify "@".
| is_proxied               | Optional[bool] | "is_proxied": true    | Enable or disable proxying for this (sub)domain. Overrides *default_is_proxied* from *zone settings*.
| ttl                      | Optional[bool] | "ttl": 1500           | The TTL value that will be set for this (sub)domain. Overrides *default_ttl* from zone *settings*.

### Repeat settings
| Variable                 | Type           | Example               | Description                                             |
| ------------------------ | -------------- | --------------------- | ------------------------------------------------------- |
| enabled                  | Optional[bool] | "enabled": true       | Enable or disable repeat updates every N-th time interval.
| delay                    | Optional[int]  | "delay": 300          | Delay between updates in seconds.

### Logging settings
| Variable                 | Type           | Example                                                  | Description                                             |
| ------------------------ | -------------- | -------------------------------------------------------- | ------------------------------------------------------- |
| level                    | Optional[str]  | "level": "DEBUG"                                         | Logging verbosity level. **Note:** The *--verbose* command line argument has a higher priority.
| formatter                | Optional[str]  | "formatter": "[%(levelname)s] %(asctime)s | %(message)s" | Log formatter. See *"python3 logging formatter"*.
</details>

<details>
<summary><b> # Another config example</b></summary>

```json
{
  "cloudflare": [
    {
      "authentication": {
        "api_key":
        {
          "account_email": "admin@coolsite.example",
          "api_key": "eXampLE-0123456789-LYnXes-are-c0ol-01234"
        }
      },
      "zone_id": "1234567890abcdefghijkl0123456789",
      "subdomains": [
        {"name": "@"},
        {"name": "www"},
        {"name": "files", "ttl": 1500},
        {"name": "proxied", "is_proxied": true}
      ],
      "default_is_proxied": false,
      "default_ttl": 300
    },
    {
      "authentication": {
          "api_token": "eXampLE-0123456789-A1l-c4ts-ar3-c0ol-012"
      },
      "zone_id": "abcdefghijkl12345678900123456789",
      "subdomains": [
        {"name": "@"},
        {"name": "www"},
        {"name": "mail", "ttl": 300}, 
        {"name": "notproxied", "is_proxied": false},
        {"name": "idk", "ttl": 900, "is_proxied": false}
      ],
      "default_is_proxied": true,
      "default_ttl": 600
    }
  ],
  "a": true,
  "aaaa": false,
  "purge_unknown_records": false,
  "repeat": {
    "enabled": true,
    "delay": 300
  },
  "logging": {
    "level": "INFO",
    "formatter": "[%(levelname)s] %(asctime)s | %(message)s"
  }
}
```
</details>

## Command line arguments

**Note:** Command line arguments have a higher priority than options in the config or environment variables

| Argument       | Aliases        | Type    | Example                         | Description                                             |
| -------------- | -------------- | ------- | --------------------------------| ------------------------------------------------------- |
| --config       | -c             | str     | --config /etc/cddns/config.json | Full path to the config, including the config file name
| --verbose      | -v             | str     | --verbose DEBUG                 | Logging verbose level
| --repeat       | -r             | bool    | --repeat True                   | Enable or disable repeat updates every N-th time interval.
| --repeat-delay | -rd            | int     | --repeat-delay 300              | Delay between regular updates (in seconds)
| --docker       | -d             | bool    | --docker True                   | "Docker mode". Wait 60 seconds before exit to prevent excessive logging on docker auto restart.

## Environment variables

| Variable          | Example                                  | Description                                             |
| ----------------- | ---------------------------------------- | ------------------------------------------------------- |
| CDDNS_CONFIG_PATH | CDDNS_CONFIG_PATH=/etc/cddns/config.json | Full path to the config, including the config file name
| CDDNS_DOCKER      | CDDNS_DOCKER=1                           | "Docker mode". Wait 60 seconds before exit to prevent excessive logging on docker auto restart.

## Default values

These values will be used if certain parameters in the config or command line arguments are not specified. They can also be changed, but by editing the script.

|                          | Default                                     |    
| ------------------------ | ------------------------------------------- | 
| Config path              | $cwd/config.json                            |
| "Docker mode"            | False                                       |
| Subdomain is proxied?    | False                                       |
| Subdomain TTL            | 300                                         |
| Repeat enabled?          | False                                       |
| Repeat delay (in seconds)| 300                                         |
| Logging verbosity level  | INFO                                        |
| Logging formatter        | "[%(levelname)s] %(asctime)s \| %(message)s"|

## Deploy with Linux + Cron

### Running (all distros)

This script requires Python 3.5+, which comes preinstalled on the latest version of Raspbian. Download/clone this repo and give permission to the project's bash script by running `chmod +x ./start-sync.sh`. Now you can execute `./start-sync.sh`, which will set up a virtualenv, pull in any dependencies, and fire the script.

1. Upload the cloudflare-ddns folder upload it wherever you want, for example, to your home directory /home/your_username_here/

2. Run the following code in terminal

```bash
crontab -e
```

3. Add the following lines to sync your DNS records every 15 minutes

```bash
*/15 * * * * /home/your_username_here/cloudflare-ddns/start-sync.sh
```

## Notes and QA

**Q1:** I have an error "IPv4 not detected", what should I do?<br>
**A1:** Try to edit the script a little. Comment out the first TRACE_CGI_IPV4 and try the second option.

Before:
```python
TRACE_CGI_IPV4: str = "https://1.1.1.1/cdn-cgi/trace"
# TRACE_CGI_IPV4: str = "https://dns.cloudflare.com/cdn-cgi/trace"
```
After:
```python
# TRACE_CGI_IPV4: str = "https://1.1.1.1/cdn-cgi/trace"
TRACE_CGI_IPV4: str = "https://dns.cloudflare.com/cdn-cgi/trace"
```
I only have IPv4, it helped. However, I don't know how this will work if you have both IPv4 and IPv6.

**Q2:** Where is the Docker version?<br>
**A2:** I don't know how to create containers for Docker yet. And I don't know if it's necessary at all. Run a 500-line Python script in a separate VM... Isn't it too irrational?

## License

This Template is licensed under the GNU General Public License, version 3 (GPLv3).

## Authors

The author of the original project - Timothy Miller \[[GitHub](https://github.com/timothymiller)\] \[[Site](https://timknowsbest.com)\]

Fork author - notssh \[[GitHub](https://github.com/notssh)\]
