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
import dns.version
from dns.exception import DNSException
import subprocess
import textwrap
import shutil
from argparse import ArgumentParser
import yaml
import validators

config = {
    # Blocklist download request timeout
    'req_timeout_s': 10,
    # Also block *.domain.tld
    'wildcard_block': False,
    # Cache directory
    'cache': Path(os.path.dirname(os.path.realpath(__file__)), )
}

parent_dir = os.path.dirname(os.path.realpath(__file__))
main_conf_file = os.path.join(parent_dir, 'config.yml')
config = yaml.safe_load(open(main_conf_file))
config['cache'] = Path(config['cache'])
if not config['cache'].is_absolute():
    config['cache'] = Path(parent_dir, config['cache'])

regex_domain = '^(127|0)\\.0\\.0\\.(0|1)[\\s\\t]+(?P<domain>([a-z0-9\\-_]+\\.)+[a-z][a-z0-9_-]*)$'
regex_no_comment = '^#.*|^$'
regex_no_comment_in_line = '^([^#]+)'

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
        with cache.open('r', encoding='utf8') as f:
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

    if not validators.domain(domain):
        print('Ignoring invalid domain {}'.format(domain))
        return False

    return True

def read_list(filename):
    path = Path(filename)
    if path.exists:
        with path.open('r', encoding='utf8') as f:
            return f.read()


def parse_lists(origin):
    domains = set()
    origin_name = dns.name.from_text(origin)
    for l in config['lists']:
        data = None
        if 'url' in l:
            print(l['url'])
            data = download_list(l['url'])
        elif 'file' in l:
            print(l['file'])
            data = read_list(l['file'])

        if data:
            lines = data.splitlines()
            print("\t{} lines".format(len(lines)))

            c = len(domains)

            for line in data.splitlines():
                domain = ''

                if re.match(regex_no_comment, line):
                    continue

                m = re.search(regex_no_comment_in_line, line)
                if m:
                    line = m.group(1).strip()

                if line == '':
                    continue

                if l.get('format', 'domain') == 'hosts':
                    m = re.match(regex_domain, line)
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

def load_zone(zonefile, origin, raw):
    zone_text = ''
    path = Path(zonefile)
    tmpPath = Path(config['cache'], 'tempzone')

    if not path.exists():
        with tmpPath.open('w') as f:
            f.write('@ 3600 IN SOA @ admin.{}. 0 86400 7200 2592000 86400\n@ 3600 IN NS LOCALHOST.'.format(origin))

        save_zone(tmpPath, zonefile, origin, raw)

        print(textwrap.dedent('''\
                Zone file "{0}" created.

                Add BIND options entry:
                response-policy {{
                    zone "{1}";
                }};

                Add BIND zone entry:
                zone "{1}" {{
                    type master;
                    file "{0}";
                    masterfile-format {2};
                    allow-query {{ none; }};
                }};
        ''').format(path.resolve(), origin, 'raw' if raw else 'text'))

    if raw:
        try:
            compile_zone(zonefile, tmpPath, origin, 'raw', 'text')
            path = tmpPath
        except:
            pass


    with path.open('r') as f:
        for line in f:
            zone_text += line
            if "IN NS" in line:
                break

    return dns.zone.from_text(zone_text, origin)

def update_serial(zone):
    soaset = zone.get_rdataset('@', dns.rdatatype.SOA)
    soa = soaset[0]
    if dns.version.MAJOR < 2:
        soa.serial += 1
    else:
        soaset.add(soa.replace(serial=soa.serial + 1))

def check_zone(origin, zonefile):
    cmd = ['named-checkzone', '-q', origin, str(zonefile)]
    r = subprocess.call(cmd)
    return r == 0

def rndc_reload(cmd):
    try:
        r = subprocess.check_output(cmd, stderr=subprocess.PIPE)

    except subprocess.CalledProcessError as e:
        print( '{}'.format( e.stderr.decode(sys.getfilesystemencoding()) ) )
        if "multiple" in e.stderr.decode('utf-8'):
            sys.exit('Please pass --views the list of configured BIND views containing origin zone.')
        if e.returncode != 0:
            sys.exit('rndc failed with return code {}'.format(e.returncode))

    print( '{}'.format( r.decode(sys.getfilesystemencoding()) ) )

def reload_zone(origin, views):
    if views:
        for v in views.split():
            print ("view {}, {} ".format(v, origin), end='', flush=True)
            rndc_reload( ['rndc', 'reload', origin, "IN", v] )
    else:
        print ("{} ".format(origin), end='', flush=True)
        rndc_reload( ['rndc', 'reload', origin] )

def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def compile_zone(source, target, origin, fromFormat, toFormat):
    cmd = ['named-compilezone', '-f', fromFormat, '-F', toFormat, '-o', str(target), origin, str(source)]
    r = subprocess.call(cmd)
    if r != 0:
        raise Exception('named-compilezone failed with return code {}'.format(r))

def save_zone(tmpzonefile, zonefile, origin, raw):
    if raw:
        compile_zone(tmpzonefile, zonefile, origin, 'text', 'raw')
    else:
        shutil.move(str(tmpzonefile), str(zonefile))

def append_domain_to_zonefile(file, domain):
    if config['blocking_mode'] == 'NXDOMAIN' or "_" in domain:
        file.write(domain + ' IN CNAME .\n')
    else:
        file.write(domain + ' IN A 0.0.0.0\n')
        file.write(domain + ' IN AAAA ::\n')

if __name__ == '__main__':
    parser = ArgumentParser(description='Update zone file from public DNS ad blocking lists')
    parser.add_argument('--no-bind', dest='no_bind', action='store_true', help='Don\'t try to check/reload bind zone')
    parser.add_argument('--raw', dest='raw_zone', action='store_true', help='Save the zone file in raw format. Requires named-compilezone')
    parser.add_argument('--empty', dest='empty', action='store_true', help='Create header-only (empty) rpz zone file')
    parser.add_argument('--views', dest='views', type=str,
                        help='If using multiple BIND views, list where each zone is defined')
    parser.add_argument('zonefile', help='path to zone file')
    parser.add_argument('origin', help='zone origin')
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    if not config['cache'].is_dir():
        config['cache'].mkdir(parents=True)

    zone = load_zone(args.zonefile, args.origin, args.raw_zone)
    update_serial(zone)

    if args.empty:
        domains = set()
    else:
        domains = parse_lists(args.origin)

    tmpzonefile = Path(config['cache'], 'tempzone')
    zone.to_file(str(tmpzonefile))

    with tmpzonefile.open('a') as f:
        for d in (sorted(domains)):        
            if d in config['domain_whitelist']:
                continue
            append_domain_to_zonefile(f, d)
            if config['wildcard_block']:
                append_domain_to_zonefile(f, '*.' + d)

    if args.no_bind:
        save_zone(tmpzonefile, args.zonefile, args.origin, args.raw_zone)
    else:
        if check_zone(args.origin, tmpzonefile):
            save_zone(tmpzonefile, args.zonefile, args.origin, args.raw_zone)
            if is_exe('/usr/sbin/getenforce'):
                cmd = ['/usr/sbin/getenforce']
                r = subprocess.check_output(cmd).strip()
                print('SELinux getenforce output / Current State is: ',r)
                if r == b'Enforcing':
                    print('SELinux restorecon being run to reset MAC security context on zone file')
                    if is_exe('/sbin/restorecon'):
                        cmd = ['/sbin/restorecon', '-F', args.zonefile]
                        r = subprocess.call(cmd)
                        if r != 0:
                            raise Exception('Cannot run selinux restorecon on the zonefile - return code {}'.format(r))
            reload_zone(args.origin, args.views)
        else:
            print('Zone file invalid, not loading')
