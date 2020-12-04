# IP4scout

[![GitHub Release](https://img.shields.io/github/v/release/LeakIX/ip4scout)](https://github.com/LeakIX/ip4scout/releases)
[![contributions welcome](https://img.shields.io/b/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/LeakIX/ip4scout/issues)
[![Follow on Twitter](https://img.shields.io/twitter/follow/leak_ix.svg?logo=twitter)](https://twitter.com/leak_ix)

IP4scout was born from the need of having a real-time feed of open ports.
Instead of scanning Internet in one shot, it takes a ports list and probe random hosts at a predefined rate.

Scanning at 5kps for 10 ports, statistically leaves has an average of 2 weeks between 2 hosts.

Leaks are random, so is this!

## Features

- SYN/ACK scanning
- Blacklist support
- Low memory/CPU footprint
- Rate limiting

## Usage

```
ip4scout random -h
```

Displays help for the random command (only implementation atm)

|Flag           |Description  |Example|
|-----------------------|-------------------------------------------------------|-------------------------------|
|--blacklist-file     |Loads a list of network (CIDR format) from a file |ip4scout random --blacklist-file=blacklist.txt|
|--source-port        |Use this port a source for the SYN packets |ip4scout random --source-port=12345|
|--ports              |List of ports to randomly send SYN packets to|ip4scout random --port=21,23,443
|--rate-limit         |Maximum number of packet per seconds|ip4scout random --rate-limit=1000|
|--disable-recommended|Disable ip4scout's built-in list of non-recommended networks|ipscout random --disable-recommended|

## Installation Instructions

### From Binary

libpcap is required to run this software, check your distribution's package manager.

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/LeakIX/ip4scout/releases/) page.

```sh
▶ apt-get install -y libpcap0.8
▶ chmod +x ip4scout-linux-64
▶ mv ip4scout-linux-64 /usr/local/bin/ip4scout
```

### From source

You're going to need libpcap's headers and **go1.14+** to built ip4scout.

```sh
▶ apt-get install -y libpcap-dev
▶ GO111MODULE=on go get -u -v github.com/LeakIX/ip4scout/cmd/ip4scout
▶ ${GOPATH}/bin/ip4scout -h
```

## Running ip4scout

```sh
▶ ip4scout --ports=3306,9200,6379 --rate-limit=10000 --blacklist-file=blacklist.txt
```

## Handling output

ip4scout speaks [l9format](l9format) which as JSON schema targeted at network recon.

[l9filter](https://github.com/LeakIX/l9filter) allows translation between this format and plenty others.

### Human output

```sh 
▶ ip4scout --ports=3306,9200,6379|tee results.json|l9filter -i json -o human
```

Will display human-readable results on `stdout` while saving the scan results to `results.json` 


### Hostport output

```sh 
▶ ip4scout --ports=3306,9200,6379|tee results.json|l9filter -i json -o hostport
```

Will display `host:port` results on `stdout` while saving the scan results to `results.json` 