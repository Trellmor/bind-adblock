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
* [Dan Pollock's hosts file](http://someonewhocares.org/hosts/zero/)
* [MalwareDomainList.com Hosts List](https://www.malwaredomainlist.com/hostslist/hosts.txt)

## Setup

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
};
```

## Usage

    update-zonefile.py zonefile origin

* zonefile: Path to the zone file to update
* origin: Zone origin to use

Example: `update-zonefile.py /etc/bind/db.rpz.example.com rpz.example.com`

`update-zonefile.py` will update the zone file with the fetched adserver lists and issue a `rndc reload origin` afterwards.

