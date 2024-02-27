```
                  _        _            _                 _       _             
 _ __   __ _  ___| | _____| |_      ___(_)_ __ ___  _   _| | __ _| |_ ___  _ __ 
| '_ \ / _` |/ __| |/ / _ \ __|____/ __| | '_ ` _ \| | | | |/ _` | __/ _ \| '__|
| |_) | (_| | (__|   <  __/ ||_____\__ \ | | | | | | |_| | | (_| | || (_) | |   
| .__/ \__,_|\___|_|\_\___|\__|    |___/_|_| |_| |_|\__,_|_|\__,_|\__\___/|_|   
|_|                                                                             
```

This is a python package and CLI utiliy for simulating the flow of arbitrary network packets through [netfilter](https://netfilter.org/), with support for routing.

## Instalation

The package is currently not available on PyPI, but can be installed from github using pip:

```bash
pip install git+https://github.com/MikPisula/packet-simulator
```

## Usage

```
usage: packet-simulator [-h] [-s SOURCE] -d DESTINATION [-t] [-u] [-dport DESTINATION_PORT] [-sport SOURCE_PORT] [-i]
                        [-p TYPE] [-c CODE] [-v] [-r RULESET] [-o ROUTES] [-f INTERFACES]

Packet simulator for testing routing and nf_tables firewall rules

options:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        source IP address
  -d DESTINATION, --destination DESTINATION
                        destination IP address
  -t, --tcp             use TCP packet
  -u, --udp             use UDP packet
  -dport DESTINATION_PORT, --destination-port DESTINATION_PORT
                        destination port
  -sport SOURCE_PORT, --source-port SOURCE_PORT
                        source port
  -i, --icmp            use ICMP packet
  -p TYPE, --type TYPE  ICMP type
  -c CODE, --code CODE  ICMP code
  -v, --verbose
  -r RULESET, --ruleset RULESET
                        Ruleset file (`ntf -j list ruleset` output)
  -o ROUTES, --routes ROUTES
                        Routing table (`ip -j route show table all` output)
  -f INTERFACES, --interfaces INTERFACES
                        Interface table (`ip -j address show` output)
```

By default, the software will run `nft` and `ip` on the host system, which requires root priviliges. This can be avoided by supplying the ruleset, routes and interfaces in json format using `-r/--ruleset`,`-o/--routes`, and `-f/--interfaces` respectively.

Supplying the resources necessary for the simulator separately can also be particularly useful when diagnosing remote systems (without the need to install anything). Example:

```bash
admin@laptop$ cat >>remote.sh <<EOF
nft -j list ruleset > ruleset.json
ip -j a s > interfaces.json
ip -j r s t all > routes.json
EOF
admin@laptop$ scp remote.sh server:/tmp
admin@laptop$ ssh server
admin@server$ cd /tmp
admin@server$ sudo bash remote.sh
admin@server$ exit
admin@laptop$ scp server:/tmp/{interfaces,routes,ruleset}.json ./
admin@laptop$ packet-simulator -f interfaces.json -o routes.json -r ruleset.json -d 127.0.0.1
[router] Using route: 127.0.0.1/32 via lo
[firewall] hook output
[firewall] enter chain OUTPUT
[firewall] jump to chain ufw-before-logging-output
[firewall] enter chain ufw-before-logging-output
[firewall] jump to chain ufw-before-output
[firewall] enter chain ufw-before-output
[firewall] match lo == lo -> True
[firewall] accept
[firewall] OUTPUT -> accept
[simulator] output_result -> accept
[firewall] hook postrouting
[simulator] postrouting_result -> None
```

## Features

The software is in very early stages, and has limited support of netfilter functionality, lacking even IPv6 support and NAT. Nonetheless, it can simulate incoming and outgoing packets, including all inet chains. It should work on default `ufw` and `firewalld` configurations.

## Issues and Contributions

If you have any issues the software, have any kind of suggestion or want to contribute functionality, *please* open an issue on GitHub. Recreating the entirety of netfilter in userland has proven to be quite challenging, but I hope that I will be able to make this tool as complete as possible.

## Acknowledgements

This project would not be possible without the following resources:
- http://linux-ip.net/html
    - http://linux-ip.net/html/part-concepts.html
    - http://linux-ip.net/html/routing-saddr-selection.html
    - http://linux-ip.net/html/routing-saddr-selection.html
- https://wiki.nftables.org/wiki-nftables/index.php
    - https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation#ct_status_-_conntrack_status
    - https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
    - https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
- https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netfilter
    - https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netfilter/nf_conntrack_common.h#L65