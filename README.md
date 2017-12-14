# BIND ad blocker

Fetch various blocklists and generate a BIND zone from them.

Configure BIND to return `NXDOMAIN` for ad and tracking domains to stop clients from contacting them.

Requires BIND 9.8 or newer for [RPZ](https://en.wikipedia.org/wiki/Response_policy_zone) support.

Uses the following sources:

* [Peter Lowe’s Ad and tracking server list](https://pgl.yoyo.org/adservers/)
* [Malware domains](http://www.malwaredomains.com/)
* [MVPS HOSTS](http://winhelp2002.mvps.org/)
* [Adaway default blocklist](https://adaway.org/hosts.txt)
* [hpHosts Ad and Tracking servers only](https://hosts-file.net/)
* [Dan Pollock’s hosts file](http://someonewhocares.org/hosts/zero/)
* [MalwareDomainList.com Hosts List](https://www.malwaredomainlist.com/hostslist/hosts.txt)
* [StevenBlack Unified hosts file](https://github.com/StevenBlack/hosts)
* [CAMELEON](http://sysctl.org/cameleon/)
* [ZeuS domain blocklist (Standard)](https://zeustracker.abuse.ch/blocklist.php)
* [Disconnect.me Basic tracking list](https://disconnect.me/trackerprotection)
* [Disconnect.me Ad Filter list](https://disconnect.me/trackerprotection)

## Setup

### Python packages

* [requests](https://pypi.python.org/pypi/requests)
* [dnspython](https://pypi.python.org/pypi/dnspython)

These packages need to be installed to run the update script.

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
	allow-query { none; };
};
```

Create a zone file for your zone. Replace example.com with the domain you used before.
```
@ 3600 IN SOA @ admin.example.com. 0 86400 7200 2592000 86400
@ 3600 IN NS ns.example.com.
```

## Usage

    update-zonefile.py zonefile origin

* zonefile: Path to the zone file to update
* origin: Zone origin to use

Example: `update-zonefile.py /etc/bind/db.rpz.example.com rpz.example.com`

`update-zonefile.py` will update the zone file with the fetched adserver lists and issue a `rndc reload origin` afterwards.

