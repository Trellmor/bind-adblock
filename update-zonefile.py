#!/usr/bin/env python3

'''
Copyright (c) 2017 Daniel Triendl <daniel@pew.cc>

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

lists = [
    {'url': 'https://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=0'},
    {'url': 'http://mirror1.malwaredomains.com/files/justdomains'},
    {'url': 'http://winhelp2002.mvps.org/hosts.txt', 'regex': '^0\\.0\\.0\\.0\\s+(?P<domain>([a-z0-9\\-_]+\\.)+[a-z]+)$'},
    {'url': 'https://adaway.org/hosts.txt', 'regex': '^127\\.0\\.0\\.1 (?P<domain>([a-z0-9\\-_]+\\.)+[a-z]+)$'},
    {'url': 'https://hosts-file.net/ad_servers.txt', 'regex': '^127\\.0\\.0\\.1\\s+(?P<domain>([a-z0-9\\-]+\\.)+[a-z]+)$'},
    {'url': 'http://someonewhocares.org/hosts/zero/hosts', 'regex': '^0\\.0\\.0\\.0\\s+(?P<domain>([a-z0-9\\-_]+\\.)+[a-z]+)$'},
    {'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt', 'regex': '^127\\.0\\.0\\.1\\s+(?P<domain>([a-z0-9\\-]+\\.)+[a-z]+)$'}
]

def download_list(url):
    headers = None

    cache = Path('.cache', 'bind_adblock')
    if not cache.is_dir():
        cache.mkdir(parents=True)
    cache = Path(cache, hashlib.sha1(url.encode()).hexdigest())

    if cache.is_file():
        last_modified = datetime.utcfromtimestamp(cache.stat().st_mtime)
        headers = {
                'If-modified-since': eut.format_datetime(last_modified),
                'User-Agent': 'Bind adblock zonfile updater v1.0 (https://github.com/Trellmor/bind-adblock)'
                }

    try:
        r = requests.get(url, headers=headers)

        if r.status_code == 200:
            with cache.open('w') as f:
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
    with Path(zonefile).open('r') as f:
        for line in f:
            if "CNAME" in line:
                break
            zone_text += line
    return dns.zone.from_text(zone_text, origin)

def update_serial(zone):
    soa = zone.get_rdataset('@', dns.rdatatype.SOA)[0]
    soa.serial += 1

def reload_zone(origin):
    cmd = ['rndc', 'reload', origin]
    r = subprocess.call(cmd)
    if r != 0:
        raise Exception('rndc failed with return code {}'.format(r))

def usage(code=0):
    print('Usage: update-zonefile.py zonefile origin')
    exit(code)

if len(sys.argv) != 3:
    usage(1)

zonefile = sys.argv[1]
origin = sys.argv[2]

zone = load_zone(zonefile, origin)
update_serial(zone)

domains = parse_lists(origin)

zone.to_file(zonefile)

with Path(zonefile).open('a') as f:
    for d in (sorted(domains)):
        f.write(d + ' IN CNAME .\n')
        f.write('*.' + d + ' IN CNAME .\n')

reload_zone(origin)
