#!python
import argparse
import base64
import ipaddress
import logging
import telnetlib
from threading import Lock
import re
from typing import List, Union, Tuple, Dict, Generator

from flask import Flask, request, jsonify
import pymemcache
import mmh3
from pymemcache.exceptions import MemcacheError


LOG = logging.getLogger("asn2ip")
RE_AS = re.compile(r"^([Aa][Ss])?(\d+)$")
RE_WHOIS_AS = re.compile(r"^[Aa]\d+$")


class MemcacheStorage:
    def __init__(self, host: str = "127.0.0.1", port: int = 11211,
                 prefix: str = "asn2ip_", ttl: int = 86400):
        self._host = host if host.startswith("/") else (host, port)
        self._prefix = prefix
        self._ttl = ttl
        self._retry = 1
        self._lock = Lock()
        self._log = LOG.getChild("Memcache")
        
        opts = {
            "serializer": pymemcache.serde.python_memcache_serializer,
            "deserializer": pymemcache.serde.python_memcache_deserializer,
            "connect_timeout": 10,
            "timeout": 10,
            "no_delay": True,
            "key_prefix": prefix.encode("utf8")
        }
        self._client = pymemcache.Client(self._host, **opts)
        
    @staticmethod
    def _normalize_key(key):
        return base64.encodebytes(mmh3.hash_bytes(key)).strip()

    def close(self):
        with self._lock:
            self._client.quit()
            
    def __getitem__(self, key):
        key = self._normalize_key(key)
        c = 0
        while c < self._retry:
            with self._lock:
                try:
                    return self._client.get(key)
                except (ConnectionError, MemcacheError):
                    if c >= self._retry:
                        self._log.error("failed to get data for %s after %d retries", key, c)
                        raise
                    self._log.warn("Memcache connection failed, retrying...")
                    self._client.quit()
                    c += 1
                    
    def __setitem__(self, key, value):
        key = self._normalize_key(key)
        c = 0
        while c < self._retry:
            with self._lock:
                try:
                    self._client.set(key, value, expire=self._ttl)
                    return
                except (ConnectionError, MemcacheError):
                    if c >= self._retry:
                        self._log.error("failed to store data for %s after %d retries", key, c)
                        raise
                    self._log.warn("Memcache connection failed, retrying...")
                    self._client.quit()
                    c += 1


def read_whois_response(client: telnetlib.Telnet) -> List[str]:
    response = []
    state = "start"
    while True:
        r = client.read_until(b"\n").decode("ascii").rstrip()
        if r == "D":
            return []
        elif r == "C":
            return response
        elif state == "start":
            match = RE_WHOIS_AS.match(r)
            if not match:
                raise Exception("No packet start found")
            state = "response"
        elif state == "response":
            response.extend(r.split(" "))
        else:
            raise Exception("Didn't receive any expected response")


def _fetch_protocol(client: telnetlib.Telnet, asn: str, log: logging.Logger,
                    version: int, memcache: MemcacheStorage) -> List[str]:
    if version == 4:
        cmd = "!g"
    elif version == 6:
        cmd = "!6"
    else:
        raise TypeError(f"unknown ip version {version}")
    
    r = None
    if memcache:
        r = memcache[f"{asn}v{version}"]
        if r:
            log.debug("Using cached data for IPv%d@%s", version, asn)
        fetched = False
        
    if not r:
        log.debug("Fetching IPv%d for %s", version, asn)
        client.write(f"{cmd}{asn}\n".encode("ascii"))
        r = read_whois_response(client)
        fetched = True
        
    if r:
        if memcache and fetched:
            log.debug("Storing fetched data for IPv%d@%s", version, asn)
            memcache[f"{asn}v{version}"] = r
        log.debug("Found %s", ",".join(r))

    return r


def fetch_ips(asn: List[str], server: str, port: int,
              ipv4: bool = True, ipv6: bool = True, timeout: int = 10,
              memcache: MemcacheStorage = None) -> Dict[str, Tuple[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    if len(asn) <= 0:
        # nop
        return ({}, {})
    
    log = LOG.getChild("fetch_ips")
    log.info("Fetching [%s], from %s:%d", ",".join(asn), server, port)
    ip4 = {}
    ip6 = {}
    with telnetlib.Telnet(host=server, port=port, timeout=timeout) as client:
        client.write(b"!!\n")
        for i in asn:
            if ipv4:
                r = _fetch_protocol(client, i, log, 4, memcache)
                if r:
                    ip4[i] = r
            if ipv6:
                r = _fetch_protocol(client, i, log, 6, memcache)
                if r:
                    ip6[i] = r
        client.write(b"exit\n")

    response = {}
    for i in asn:
        v4 = sorted(ipaddress.ip_network(x) for x in ip4.get(i, []))
        v6 = sorted(ipaddress.ip_network(x) for x in ip6.get(i, []))
        response[i] = (v4, v6)

    return response


def normalize_asn(asn: Union[str, List[str]]) -> List[str]:
    if isinstance(asn, str):
        asn = [asn]
    if not isinstance(asn, list):
        raise TypeError("asn must be a string or list of strings")
    if len(asn) <= 0:
        return []
    if not isinstance(asn[0], str):
        raise TypeError("asn must be a string or list of strings")
    
    for i in asn:
        match = RE_AS.match(i)
        if not match:
            raise TypeError(f"Invalid ASN {i}")
        yield f"AS{match.group(2)}"


def main():
    parser = argparse.ArgumentParser(prog="asn2ip")
    parser.add_argument("--log", "-l", type=str,
                        choices=["DEBUG", "INFO", "WARN", "WARNING",
                                 "ERROR", "CRITICAL", "FATAL"],
                        default="WARN", help="Set log level. %(default)s")
    parser.add_argument("--whois-host", type=str, default="whois.radb.net",
                        help="whois host to request for ip addresses. (%(default)s)")
    parser.add_argument("--whois-port", type=int, default=43,
                        help="whois port (%(default)d)")
    
    actions = parser.add_subparsers(title="action", dest="action",
                                    help="Action to execute")
    
    action_fetch = actions.add_parser("fetch", description="Fetch specified ASN networks")
    action_fetch.add_argument("ASN", metavar="ASN", nargs="+",
                              help="ASN to fetch")
    
    action_run = actions.add_parser("run", description="Run as daemon")
    action_run.add_argument("--listen", "-L", type=str, default="0.0.0.0",
                            help="Listen address for http service")
    action_run.add_argument("--port", "-P", type=int, default=8080,
                            help="Listen port for http service")
    action_run.add_argument("--memcache", type=str,
                            help="IP:Port or absolute socket path for memcache")

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)-15s %(name)s [%(levelname)s]: %(message)s",
        level=args.log,
    )
    log = LOG.getChild("Main")
    
    if not args.action:
        log.critical("No action given")
        parser.print_help()
        exit(1)
        
    if args.action == "fetch":
        asn = list(normalize_asn(args.ASN))
        response = fetch_ips(asn, server=args.whois_host, port=args.whois_port)
        for a, (ip4, ip6) in response.items():
            print(a)
            if ip4:
                print("  IPv4:")
                for net in ip4:
                    print(f"    {str(net)}")
            if ip6:
                print("  IPv6:")
                for net in ip6:
                    print(f"    {str(net)}")
    elif args.action == "run":
        app = Flask(__name__)
        
        memcache: MemcacheStorage = None
        if args.memcache:
            host, port = args.memcache, 11211
            if not host.startswith("/"):
                host, port = host.split(":")
                port = int(port)
            memcache = MemcacheStorage(host=host, port=port)
        
        @app.route("/")
        def index():
            return """
            <html>
                <body>
                    <p>
                    This is a simple tool to pull all netblocks from an ASN into a text file output.<br/>
                    You can use this in your application (e.g. firewall like pfSense/OPNsense) to filter or prioritize
                    specific services.
                    </p>
                    <h2>How to use</h2>
                    <p>
                    To use this service just send a GET request with the ASN number as path.<br/>
                    You may also request multiple ASN by seperating them with a ':'.<br/>
                    <br/>
                    Examples:<br/>
                    Netflix <a href="https://asn.copr.icu/2906">https://asn.copr.icu/2906</a><br/>
                    Netflix and Twitch <a href="https://asn.copr.icu/2906:46489">https://asn.copr.icu/2906:46489</a>
                    </p>
                    <h2>Options</h2>
                    <p>
                    You can use the following options in your GET request to control the output of this tool.
                    </p>
                    <table>
                        <tr>
                            <th>Option</th>
                            <th>Type</th>
                            <th>Description</th>
                            <th>Default</th>
                        </tr>
                        <tr>
                            <td>ipv4</td>
                            <td>Boolean (y, yes, true)</td>
                            <td>Output IPv4 addresses.</td>
                            <td>true</td>
                        </tr>
                        <tr>
                            <td>ipv6</td>
                            <td>Boolean (y, yes, true)</td>
                            <td>Output IPv6 addresses.</td>
                            <td>true</td>
                        </tr>
                        <tr>
                            <td>seperator</td>
                            <td>String</td>
                            <td>Use this as the seperator between IP-Addresses</td>
                            <td>[[:space:]]</td>
                        </tr>
                        <tr>
                            <td>json</td>
                            <td>Boolean (y, yes, true)</td>
                            <td>Output as json instead of plain text</td>
                            <td>false</td>
                        </tr>
                    </table>
                    
                    <p>
                    Examples:<br/>
                    Netflix IPv4 only <a href="https://asn.copr.icu/2906?ipv4=true&ipv6=false">https://asn.copr.icu/2906?ipv4=true&ipv6=false</a><br/>
                    Twitch as JSON <a href="https://asn.copr.icu/46489?json=yes">https://asn.copr.icu/46489?json=yes</a><br/>
                    Twitch comma seperated <a href="https://asn.copr.icu/46489?seperator=%2C">https://asn.copr.icu/46489?seperator=%2C</a>
                    </p>
                </body>
            </html>
            """
            
        @app.route("/<asn>")
        def fetch(asn):
            try:
                asn = list(normalize_asn(asn.split(":")))
            except TypeError as err:
                return str(err)
            
            ipv4 = bool(request.args.get("ipv4", "true").lower() in ["y", "yes", "true"])
            ipv6 = bool(request.args.get("ipv6", "true").lower() in ["y", "yes", "true"])
            json = bool(request.args.get("json", "false").lower() in ["y", "yes", "true"])
            seperator = request.args.get("seperator", " ")
            
            response = fetch_ips(asn, server=args.whois_host, port=args.whois_port,
                                 ipv4=ipv4, ipv6=ipv6, memcache=memcache)
            
            if json:
                json_response = {}
                for a, (ip4, ip6) in response.items():
                    json_response[a] = {"ipv4": [str(x) for x in ip4],
                                        "ipv6": [str(x) for x in ip6]}
                return jsonify(json_response)
            else:
                allip = []
                for a, (ip4, ip6) in response.items():
                    allip.extend(ip4)
                    allip.extend(ip6)
                return seperator.join(str(x) for x in allip)
            
        app.run(host=args.listen, port=args.port, debug=args.log == "DEBUG")

if __name__ == '__main__':
    main()