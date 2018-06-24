#!/usr/bin/env python3

'''
Copyright (c) 2018 Daniel Triendl <daniel@pew.cc>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

import requests
from pathlib import Path
from datetime import datetime
import email.utils as eut
import os
import hashlib
import re
import sys
import dns.zone
import dns.name
from dns.exception import DNSException
import subprocess
import textwrap
import shutil
from argparse import ArgumentParser

config = {
    # Blocklist download request timeout
    'req_timeout_s': 10,
    # Also block *.domain.tld
    'wildcard_block': False,
    # Cache directory
    'cache': Path('.cache', 'bind_adblock')
}

regex_domain = '^(127|0)\\.0\\.0\\.(0|1)[\\s\\t]+(?P<domain>([a-z0-9\\-_]+\\.)+[a-z][a-z0-9_-]*)$'
regex_no_comment = '^#.*|^$'

lists = [
    {'url': 'https://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=0', 'filter': regex_no_comment},
    {'url': 'http://mirror1.malwaredomains.com/files/justdomains', 'filter': regex_no_comment},
    {'url': 'http://winhelp2002.mvps.org/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'https://adaway.org/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'https://hosts-file.net/ad_servers.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'http://someonewhocares.org/hosts/zero/hosts', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},

    #
    # adlists from pi-hole: https://github.com/pi-hole/pi-hole/blob/master/adlists.default
    #
    # The below list amalgamates several lists we used previously.
    # See `https://github.com/StevenBlack/hosts` for details
    # StevenBlack's list
    {'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'regex': regex_domain, 'filter': regex_no_comment},

    # Cameleon
    {'url': 'http://sysctl.org/cameleon/hosts', 'regex': regex_domain, 'filter': regex_no_comment},

    # Zeustracker
    {'url': 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist', 'filter': regex_no_comment},

    # Disconnect.me Tracking
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', 'filter': regex_no_comment},

    # Disconnect.me Ads
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt', 'filter': regex_no_comment},

    # Suspicious Domains - SANS ISC
    {'url': 'https://isc.sans.edu/feeds/suspiciousdomains_Low.txt', 'filter': regex_no_comment},

]

def download_list(url):
    headers = None

    cache = Path(config['cache'], hashlib.sha1(url.encode()).hexdigest())

    if cache.is_file():
        last_modified = datetime.utcfromtimestamp(cache.stat().st_mtime)
        headers = {
                'If-modified-since': eut.format_datetime(last_modified),
                'User-Agent': 'Bind adblock zonfile updater v1.0 (https://github.com/Trellmor/bind-adblock)'
                }

    try:
        r = requests.get(url, headers=headers, timeout=config['req_timeout_s'])

        if r.status_code == 200:
            with cache.open('w', encoding='utf8') as f:
                f.write(r.text)
            if 'last-modified' in r.headers:
                last_modified = eut.parsedate_to_datetime(r.headers['last-modified']).timestamp()
                os.utime(str(cache), times=(last_modified, last_modified))

            return r.text
    except requests.exceptions.RequestException as e:
        print(e)

    if cache.is_file():
        with cache.open() as f:
            return f.read()

def check_domain(domain, origin):
    if domain == '':
        return False

    if config['wildcard_block']:
        domain = '*.' + domain

    try:
        name = dns.name.from_text(domain, origin)
    except DNSException as e:
        return False

    return True

def parse_lists(origin):
    domains = set()
    origin_name = dns.name.from_text(origin)
    for l in lists:
        data = download_list(l['url'])
        if data:
            print(l["url"])

            lines = data.splitlines()
            print("\t{} lines".format(len(lines)))

            c = len(domains)

            for line in data.splitlines():
                domain = ''

                if 'filter' in l:
                    m = re.match(l['filter'], line)
                    if m:
                        continue

                if 'regex' in l:
                    m = re.match(l['regex'], line)
                    if m:
                        domain = m.group('domain')
                else:
                    domain = line

                domain = domain.strip()
                if check_domain(domain, origin_name):
                    domains.add(domain)

            print("\t{} domains".format(len(domains) - c))

    print("\nTotal\n\t{} domains".format(len(domains)))
    return domains

def load_zone(zonefile, origin):
    zone_text = ''
    path = Path(zonefile)

    if not path.exists():
        with path.open('w') as f:
            f.write('@ 3600 IN SOA @ admin.{}. 0 86400 7200 2592000 86400\n@ 3600 IN NS LOCALHOST.'.format(origin))

        print(textwrap.dedent('''\
                Zone file "{0}" created.

                Add BIND options entry:
                response-policy {{
                    zone "{1}"
                }};

                Add BIND zone entry:
                zone "{1}" {{
                    type master;
                    file "{0}";
                    allow-query {{ none; }};
                }};
        ''').format(path.resolve(), origin))


    with path.open('r') as f:
        for line in f:
            if "CNAME" in line:
                break
            zone_text += line

    return dns.zone.from_text(zone_text, origin)

def update_serial(zone):
    soa = zone.get_rdataset('@', dns.rdatatype.SOA)[0]
    soa.serial += 1

def check_zone(origin, zonefile):
    cmd = ['named-checkzone', '-q', origin, str(zonefile)]
    r = subprocess.call(cmd)
    return r == 0

def reload_zone(origin):
    cmd = ['rndc', 'reload', origin]
    r = subprocess.call(cmd)
    if r != 0:
        raise Exception('rndc failed with return code {}'.format(r))

if __name__ == '__main__':
    parser = ArgumentParser(description='Update zone file from public DNS ad blocking lists')
    parser.add_argument('--no-bind', dest='no_bind', action='store_true', help='Don\'t try to check/reload bind zone')
    parser.add_argument('zonefile', help='path to zone file')
    parser.add_argument('origin', help='zone origin')
    args = parser.parse_args()

    zone = load_zone(args.zonefile, args.origin)
    update_serial(zone)

    if not config['cache'].is_dir():
        config['cache'].mkdir(parents=True)

    domains = parse_lists(args.origin)

    tmpzonefile = Path(config['cache'], 'tempzone')
    zone.to_file(str(tmpzonefile))

    with tmpzonefile.open('a') as f:
        for d in (sorted(domains)):
            f.write(d + ' IN CNAME .\n')
            if config['wildcard_block']:
                f.write('*.' + d + ' IN CNAME .\n')

    if args.no_bind:
        shutil.move(str(tmpzonefile), str(args.zonefile))
    else:
        if check_zone(args.origin, tmpzonefile):
            shutil.move(str(tmpzonefile), str(args.zonefile))
            reload_zone(args.origin)
        else:
            print('Zone file invalid, not loading')
