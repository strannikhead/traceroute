# traceroute
Tool for displaying possible routes (paths) and transit delays of packets across network.

## Usage
Program use raw sockets, use root access for usage.
```
$ sudo python3 traceroute.py [OPTIONS] destination
```

## Options
- `-b` packet size in bytes
- `-m` max hopes
- `-t` timeout
- `-i` interval
- `-d` debug mode
