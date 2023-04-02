# BIND ad blocker

Fetch various blocklists and generate a BIND zone from them.

Configure BIND to return `NXDOMAIN` for ad and tracking domains to stop clients from contacting them.

Requires BIND 9.8 or newer for [RPZ](https://en.wikipedia.org/wiki/Response_policy_zone) support.

Uses the following sources:

* [Peter Lowe’s Ad and tracking server list](https://pgl.yoyo.org/adservers/)
* [MVPS HOSTS](http://winhelp2002.mvps.org/)
* [Adaway default blocklist](https://adaway.org/hosts.txt)
* [Dan Pollock’s hosts file](http://someonewhocares.org/hosts/zero/)
* [MalwareDomainList.com Hosts List](http://www.malwaredomainlist.com/hostslist/hosts.txt)
* [StevenBlack Unified hosts file](https://github.com/StevenBlack/hosts)
* [CAMELEON](http://sysctl.org/cameleon/)
* [Disconnect.me Basic tracking list](https://disconnect.me/trackerprotection)
* [Disconnect.me Ad Filter list](https://disconnect.me/trackerprotection)
* [Polish CERT Phishing list](https://www.cert.pl/ostrzezenia_phishing/)

## Setup

### Python packages

See [requirements.txt](requirements.txt)

To install
```
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```


### Configure BIND

Add the `response-policy` statement to the BIND options

```
// For AdBlock
response-policy {
	zone "rpz.example.com";
};
```

Add your rpz zone. Replace example.com with a domain of your choice.

```
// AdBlock
zone "rpz.example.com" {
	type master;
	file "/etc/bind/db.rpz.example.com";
	masterfile-format text;
	allow-query { none; };
};
```

Create a zone file for your zone. Replace example.com with the domain you used before.
```
@ 3600 IN SOA @ admin.example.com. 0 86400 7200 2592000 86400
@ 3600 IN NS ns.example.com.
```

## Usage

    usage: update-zonefile.py [-h] [--no-bind] [--raw] [--empty] zonefile origin

    Update zone file from public DNS ad blocking lists

    positional arguments:
      zonefile    path to zone file
      origin      zone origin

    optional arguments:
      -h, --help  show this help message and exit
      --no-bind   Don't try to check/reload bind zone
      --raw       Save the zone file in raw format. Requires named-compilezone
      --empty     Create header-only (empty) rpz zone file

Example: `update-zonefile.py /etc/bind/db.rpz.example.com rpz.example.com`

`update-zonefile.py` will update the zone file with the fetched adserver lists and issue a `rndc reload origin` afterwards.

## Whitelist

You can either use an additional zone to whitelist domains (Or add them to `config.yml`) 
See [Whitelist](https://github.com/Trellmor/bind-adblock/wiki/whitelist) for adding a whitelist zone.
