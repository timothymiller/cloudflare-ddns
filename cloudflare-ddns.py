#!/usr/bin/env python
#   cloudflare-ddns-enhanced.py
#   Summary: Access your home network remotely via a custom domain name without a static IP!
#   Description: Access your home network remotely via a custom domain

__version__ = "1.0.2e"

import json
import os
import signal
import sys
import threading
import time
import requests
import logging
import argparse
from typing import Optional, Dict

#
DEF_CONFIG_PATH: str = os.environ.get('CDDNS_CONFIG_PATH', os.path.join(os.getcwd(), "config.json"))
DOCKER: bool = os.environ.get('CDDNS_DOCKER').lower() in ('true', '1', 't') if os.environ.get('CDDNS_DOCKER') else False

# Default values for some variables, if they are not specified in the config.
# It's better to just add what you need to the config than change them here.
DEF_SUBDOMAIN_IS_PROXIED: bool = False
DEF_SUBDOMAIN_TTL: int = 300
DEF_REPEAT: bool = False
DEF_REPEAT_DELAY: int = 300  # seconds
DEF_VERBOSE_LEVEL: str = "INFO"
DEF_LOG_FORMATTER: str = "[%(levelname)s] %(asctime)s | %(message)s"

# Some Cloudflare stuff. It's better not to touch it if you don't know what you're doing.
CLOUDFLARE_API: str = 'https://api.cloudflare.com/client/v4/'
# If it doesn't work ("IPv4 not detected" error), comment out the first one and try the second option.
# I only have IPv4, it helped. However, I don't know how this will work if you have both IPv4 and IPv6.
TRACE_CGI_IPV4: str = "https://1.1.1.1/cdn-cgi/trace"
# TRACE_CGI_IPV4: str = "https://dns.cloudflare.com/cdn-cgi/trace"
TRACE_CGI_IPV6: str = "https://[2606:4700:4700::1111]/cdn-cgi/trace"  # idk, sorry.


LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARN,
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "FATAL": logging.FATAL
}


class InvalidCredentials(Exception):
    pass


class CloudflareApiException(Exception):
    pass


class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        log.warning("Stopping main thread...")
        self.kill_now.set()


def delete_entries(record_type):
    # Helper function for deleting A or AAAA records
    # in the case of no IPv4 or IPv6 connection, yet
    # existing A or AAAA records are found.

    for option in config["cloudflare"]:
        answer = cf_api("GET",
                        f"zones/{option['zone_id']}/dns_records?per_page=100&type={record_type}",
                        option)
        if answer is None or answer["result"] is None:
            time.sleep(5)
            return
        for record in answer["result"]:
            identifier = str(record["id"])
            cf_api("DELETE",
                   f"zones/{option['zone_id']}/dns_records/{identifier}",
                   option)
            log.info(f"Deleted stale record {identifier}")


def get_ips():
    a = None
    aaaa = None
    global ipv4_enabled
    global ipv6_enabled
    global purge_unknown_records
    if ipv4_enabled:
        try:
            a = requests.get(TRACE_CGI_IPV4).text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception as e:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                log.error(f"IPv4 not detected: {e}")
            if purge_unknown_records:
                delete_entries("A")
    if ipv6_enabled:
        try:
            aaaa = requests.get(TRACE_CGI_IPV6).text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception as e:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                log.error(f"IPv6 not detected: {e}")
            if purge_unknown_records:
                delete_entries("AAAA")
    ips = {}
    if a is not None:
        log.info(f'Your IPv4 address is {a}')
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if aaaa is not None:
        log.info(f'Your IPv6 address is {aaaa}')
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    return ips


def commit_record(ip):
    config_counter = 0
    for option in config["cloudflare"]:
        config_counter += 1
        if not option.get('zone_id'):
            log.error(f"zone_id for config #{config_counter} is not specified! Skipping...")
            continue
        if not option.get('subdomains'):
            log.error(f"Subdomains for config #{config_counter} (zone_id {option['zone_id']}) "
                      f"are not specified! Skipping...")
            continue

        subdomains: dict = option["subdomains"]
        try:
            response = cf_api("GET",
                              f"zones/{option['zone_id']}",
                              option)
        except CloudflareApiException as cf_exc:
            log.error(cf_exc)
            continue
        except InvalidCredentials:
            log.error(f"Credentials for zone {option['zone_id']} are not specified! Skipping...")
            continue
        if response is None or response["result"]["name"] is None:
            log.error(f"Zone {option['zone_id']} - error, information was not received from the API! Skipping...")
            time.sleep(5)
            continue
        base_domain_name = response["result"]["name"]
        subdomain_counter = 0
        try:
            dns_records = cf_api("GET",
                                 f"zones/{option['zone_id']}/dns_records?per_page=100&type={ip['type']}",
                                 option)
        except CloudflareApiException as cf_exc:
            log.error(cf_exc)
            continue

        for subdomain in subdomains:
            subdomain_counter += 1

            subdomain: dict
            subdomain_name: Optional[str] = subdomain.get("name", None)
            subdomain_is_proxied: bool = subdomain.get("is_proxied", option.get("default_is_proxied",
                                                                                DEF_SUBDOMAIN_IS_PROXIED))
            subdomain_ttl: int = subdomain.get("ttl", option.get("default_ttl", DEF_SUBDOMAIN_TTL))

            if subdomain_name is not None and subdomain_name == '':
                log.error(f"Subdomain #{subdomain_counter} name in config #{config_counter} "
                          f"(zone_id {option['zone_id']}) is invalid! Specify @ to update the root record. Skipping...")
                continue
            elif subdomain_name is not None:
                fqdn = base_domain_name if subdomain_name == '@' else subdomain_name + "." + base_domain_name
            else:
                log.error(f"Subdomain #{subdomain_counter} name in config #{config_counter} "
                          f"(zone_id {option['zone_id']}) is not specified! Skipping...")
                continue
            record = {
                "type": ip["type"],
                "name": fqdn,
                "content": ip["ip"],
                "zone_id": option['zone_id'],
                "proxied": subdomain_is_proxied,
                "ttl": subdomain_ttl
            }
            identifier = None
            modified = False

            if dns_records is not None:
                for r in dns_records["result"]:
                    if r["name"] == fqdn:
                        identifier = r["id"]
                        if r['content'] != record['content'] \
                                or r['proxied'] != record['proxied'] \
                                or r['ttl'] != record['ttl']:
                            modified = True
            try:
                if identifier:
                    if modified:
                        log.info(f"Updating record {str(record)}")
                        record["id"] = identifier
                        cf_api("PUT",
                               f"zones/{option['zone_id']}/dns_records/{identifier}",
                               option, None, record)
                else:
                    log.info("Adding new record " + str(record))
                    cf_api("POST",
                           f"zones/{option['zone_id']}/dns_records/",
                           option, None, record)
            except CloudflareApiException as cf_exc:
                log.error(cf_exc)
    return True


def cf_api(method: str, endpoint: str, cf_config: dict, headers: Optional[dict] = None, data: Optional[dict] = None):
    headers = {} if headers is None else headers
    auth_settings = cf_config.get('authentication')
    if auth_settings:
        api_token: Optional[str] = auth_settings.get('api_token')
        api_key: Optional[dict] = auth_settings.get('api_key')

        if api_token is not None:
            if api_token != '' and api_token != 'api_token_here':
                headers = {
                    "Authorization": "Bearer " + api_token,
                    **headers
                }
            else:
                raise InvalidCredentials
        elif api_key is not None:
            account_email = api_key.get('account_email')
            api_key = api_key.get('api_key')
            if account_email and api_key:
                headers = {
                    "X-Auth-Email": account_email,
                    "X-Auth-Key": api_key,
                    **headers
                }
            else:
                raise InvalidCredentials
        else:
            raise InvalidCredentials
        try:
            log.debug(f"[CF_API] REQUEST\n"
                      f"================================================\n"
                      f">> {method} {CLOUDFLARE_API + endpoint}\n"
                      f">> Client headers: {headers}\n"
                      f">> Payload: {data}\n"
                      f"================================================")
            response = requests.request(
                method,
                CLOUDFLARE_API + endpoint,
                headers=headers,
                json=data if data is not None else None
            )
            log.debug(f"[CF_API] RESPONSE\n"
                      f"================================================\n"
                      f"<< {method} {response.url}\n"
                      f"<< Status: {response.status_code} [{'OK' if response.ok else 'FAILED'}]\n"
                      f"<< Headers: {response.headers}\n"
                      f"<< Content: {response.content}\n"
                      f"<< Elapsed time: {response.elapsed}\n"
                      f"================================================")
            if response.ok:
                return response.json()
            else:
                raise CloudflareApiException(f"Error sending '{method}' "
                                             f"request to '{response.url}':\n{response.text}")
        except Exception as e:
            raise CloudflareApiException(f"An exception occurred while sending '{method}' "
                                         f"request to '{CLOUDFLARE_API + endpoint}':\n{e}")
    else:
        raise InvalidCredentials


def update_ips(ips: Dict[str, Dict]):
    for ip in ips.values():
        commit_record(ip)


if __name__ == '__main__':
    shown_ipv4_warning = False
    shown_ipv6_warning = False
    purge_unknown_records = False

    parser = argparse.ArgumentParser(description=f'# Cloudflare DDNS Enhanced v{__version__} '
                                                 f'// Refreshed fork by @notssh\n\n',
                                     epilog='Random fact of this release: according to the University of Lyon: '
                                            'there are about 400 million domestic cats in the world. '
                                            'The leader is Australia, where there are 9 cats per 10 inhabitants.')
    parser.add_argument('-c', '--config',
                        type=str,
                        help=f'Full path to the config, including the config file name. '
                             f'The default value also can be changed by the environment '
                             f'variable "CDDNS_CONFIG_PATH". '
                             f'Default: {os.environ.get("CDDNS_CONFIG_PATH", "$cwd/config.json")}')
    parser.add_argument('-v', '--verbose',
                        type=str,
                        choices=LOG_LEVELS.keys(),
                        help=f'Logging verbose level. Default: {DEF_VERBOSE_LEVEL}')
    parser.add_argument('-r', '--repeat',
                        type=bool,
                        choices=[True, False],
                        help=f'Enable or disable repeat updates every N-th time interval.. '
                             f'Default: {DEF_REPEAT}')
    parser.add_argument('-rd', '--repeat-delay',
                        type=int,
                        help=f'Delay between regular updates (in seconds). '
                             f'Default: {DEF_REPEAT_DELAY}')
    parser.add_argument('-d', '--docker',
                        type=bool,
                        choices=[True, False],
                        help=f'"Docker mode". '
                             f'Wait 60 seconds before exit to prevent excessive logging on docker auto restart. '
                             f'The default value also can be changed by the environment variable "CDDNS_DOCKER". '
                             f'Default: {DOCKER}')

    cmd_args = parser.parse_args()

    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    log_formatter = logging.Formatter(DEF_LOG_FORMATTER)
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(LOG_LEVELS.get(DEF_VERBOSE_LEVEL.upper(), logging.INFO))
    log.addHandler(console_handler)

    if sys.version_info < (3, 5):
        log.error("This script requires Python 3.5+")
        exit()

    config: Optional[dict] = None
    config_path: str = cmd_args.config if cmd_args.config else DEF_CONFIG_PATH
    docker_mode: bool = cmd_args.docker if cmd_args.docker else DOCKER
    try:
        with open(config_path) as config_file:
            config = json.loads(config_file.read())
    except FileNotFoundError:
        log.error(f"Error reading {config_path}: file not found")
        if docker_mode:
            time.sleep(60)  # wait 60 seconds to prevent excessive logging on docker auto restart
    except ValueError as config_exc:
        log.error(f"Error reading {config_path}: JSON syntax error - {config_exc}")
        if docker_mode:
            time.sleep(60)
    except Exception as config_exc:
        log.error(f"Error reading {config_path}: {config_exc}")
        if docker_mode:
            time.sleep(60)

    if config is not None:
        logging_settings = config.get('logging')
        if logging_settings:
            log_formatter = logging.Formatter(logging_settings.get("formatter",
                                                                   DEF_LOG_FORMATTER))
            console_handler.setFormatter(log_formatter)
            log.setLevel(LOG_LEVELS.get(logging_settings.get("level").upper(),
                                        LOG_LEVELS.get(DEF_VERBOSE_LEVEL.upper(), logging.INFO)))
            console_handler.setLevel(LOG_LEVELS.get(logging_settings.get("level").upper(),
                                                    LOG_LEVELS.get(DEF_VERBOSE_LEVEL.upper(), logging.INFO)))
        if cmd_args.verbose:
            log.setLevel(LOG_LEVELS.get(cmd_args.verbose.upper(),
                                        LOG_LEVELS.get(DEF_VERBOSE_LEVEL.upper())))
            console_handler.setLevel(LOG_LEVELS.get(cmd_args.verbose.upper(),
                                                    LOG_LEVELS.get(DEF_VERBOSE_LEVEL.upper(), logging.INFO)))
        log.info(f"# Cloudflare DDNS Enhanced v{__version__} // Fork by @notssh")

        log.debug(f"Command line arguments: {cmd_args.__dict__}")

        ipv4_enabled: Optional[bool] = config.get('a')
        ipv6_enabled: Optional[bool] = config.get('aaaa')
        purge_unknown_records: Optional[bool] = config.get('purge_unknown_records')

        if not config.get('cloudflare'):
            log.error('Invalid config: the "cloudflare" section is missing')
            if docker_mode:
                time.sleep(60)  # wait 60 seconds to prevent excessive logging on docker auto restart
            exit()

        if ipv4_enabled is None:
            ipv4_enabled = True
            log.warning("Individually disable IPv4 with new config options. "
                        "Read more about it here: "
                        "https://github.com/notssh/cloudflare-ddns-enhanced/blob/master/README.md")
        if ipv6_enabled is None:
            ipv6_enabled = True
            log.warning("Individually disable IPv6 with new config options. "
                        "Read more about it here: "
                        "https://github.com/notssh/cloudflare-ddns-enhanced/blob/master/README.md")
        if purge_unknown_records is None:
            purge_unknown_records = False
            log.warning(f"Variable 'purge_unknown_records' is not specified in config. "
                        f"Defaulting to {purge_unknown_records}")

        repeat = DEF_REPEAT
        repeat_delay = DEF_REPEAT_DELAY
        repeat_config: Optional[dict] = config.get('repeat')
        if repeat_config:
            repeat = repeat_config.get('enabled', DEF_REPEAT)
            repeat_delay = repeat_config.get('delay', DEF_REPEAT_DELAY)
        if cmd_args.repeat:
            repeat = cmd_args.repeat
        if cmd_args.repeat_delay:
            repeat_delay = cmd_args.repeat_delay
        if repeat:
            if ipv4_enabled and ipv6_enabled:
                log.info(f"Updating IPv4 (A) & IPv6 (AAAA) records every {repeat_delay} seconds "
                         f"(~{round(repeat_delay/60)} minutes)")
            elif ipv4_enabled and not ipv6_enabled:
                log.info(f"Updating IPv4 (A) records every {repeat_delay} seconds "
                         f"(~{round(repeat_delay/60)} minutes)")
            elif ipv6_enabled and not ipv4_enabled:
                log.info(f"Updating IPv6 (AAAA) records every {repeat_delay} seconds "
                         f"(~{round(repeat_delay/60)} minutes)")
            next_time = time.time()
            killer = GracefulExit()
            prev_ips = None
            while True:
                update_ips(get_ips())
                if killer.kill_now.wait(repeat_delay):
                    break
        else:
            update_ips(get_ips())
            log.info('Done!')
