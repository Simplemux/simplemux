Simplemux
=========

# Introduction

There are some situations in which multiplexing a number of small packets into a bigger one is desirable. For example, a number of small packets can be sent together between a pair of machines if they share a common network path. Thus, the traffic profile can be shifted from small to larger packets, reducing the network overhead and the number of packets per second to be managed by intermediate routers.

In other cases it is necessary to send tunneled packets or frames between different network locations.

Multiplexing can be combined with Tunneling and Header Compression for the optimization of small-packet flows. This is called TCM. Different algorithms for header compression, multiplexing and tunneling can be combined in a similar way to RFC 4170.

Simplemux is a protocol able to encapsulate a number of packets belonging to different protocols into a single packet. It includes the "Protocol" field on each multiplexing header, thus allowing the inclusion of a number of packets belonging to different protocols on a packet of another protocol.

```

         +--------------------------------+
         |       Multiplexed Packet       |     Multiplexed protocol
         +--------------------------------+
         |      Multiplexing header       |     Multiplexing protocol (Simplemux)
         +--------------------------------+
         |       Tunneling header         |     Tunneling protocol
         +--------------------------------+
```

This is the structure of a packet including three multilplexed packets:

```
+-----------------+---------+----------------+---------+----------------+---------+----------------+
|Tunneling header |simplemux| muxed packet 1 |simplemux| muxed packet 2 |simplemux| muxed packet 3 |
+-----------------+---------+----------------+---------+----------------+---------+----------------+
```

The size of the simplemux separators is kept very low (it may be a single byte when multiplexing small packets) in order to reduce the overhead.

# About this repository

This repository includes a Linux user-space implementation of Simplemux, written in C. It uses Simplemux as the multiplexing protocol, and different options for the multiplexed and tunneling protocols:
- Multiplexed protocol: Ethernet, IP, RoHC (RFC 5795).
- Multiplexing protocol: Simplemux.
- Tunneling protocol: IP, TCP/IP or UDP/IP,

IPv6 is not supported in this implementation.

# Modes and flavors

## Tunnel modes

Simplemux has two *tunnel modes*, so it can include the next multiplexed protocols:

- **Tun mode**: it aggregates IP or RoHC (RFC 5795) packets. RoCH feedback messages are always sent in IP/UDP packets.
- **Tap mode**: it aggregates Ethernet frames.


## Modes

It includes the next options for the *tunneling* protocol, which correspond to four *modes*:

- **Network mode**: the multiplexed packet is sent in an **IP datagram** using Protocol Number 253 or 254 (according to IANA, these numbers can be used for experimentation and testing ).
- **UDP mode**: the multiplexed packet is sent in an **UDP/IP** datagram. In this case, the protocol number in the outer IP header is that of UDP (17) and both ends must agree on a UDP port (the implementation uses 55555 or 55557 by default).
- **TCP server mode**: the multiplexed packet is sent in a **TCP/IP** datagram. In this case, the protocol number in the outer IP header is that of TCP (4) and both ends must agree on a TCP port (the implementation uses 55555 or 55557 by default).
- **TCP client mode**: as it happens in TCP server mode, **TCP/IP** datagrams are sent.


## Flavors

Simplemux has the next *flavors*:

- **Normal**: it tries to compress the separators as much as possible. For that aim, some single-bit fields are used.
- [**Fast**](https://gitlab.com/josemariasaldana/simplemux/-/blob/tun_to_net_separation/documentation/fast_flavor.md): it sacrifices some compression on behalf or speed. In this case, all the separators are 3-byte long, and all have the same structure.
In TCP *mode*, the use of Simplemux *fast* is compulsory.
- [**Blast**](https://gitlab.com/josemariasaldana/simplemux/-/blob/tun_to_net_separation/documentation/blast_flavor.md): it sends the same packet a number of times. But it only delivers one copy to the end point (the one that arrives first). It does not multiplex a number of packets together. It does NOT work in TCP mode.


The initial specification of Simplemux can be found here: http://datatracker.ietf.org/doc/draft-saldana-tsvwg-simplemux/. It was never adopted by the IETF, although some discussion take place. Note: It only specifies the *Normal* flavor.

A research paper about Simplemux can be found here: http://diec.unizar.es/~jsaldana/personal/chicago_CIT2015_in_proc.pdf

A presentation about Simplemux can be found here: http://es.slideshare.net/josemariasaldana/simplemux-traffic-optimization


# How to install and compile

[How to install RoHC and compile Simplemux](https://gitlab.com/josemariasaldana/simplemux/-/blob/tun_to_net_separation/documentation/how_to_install_and_compile.md).


# Usage examples:
```
./simplemux -i tun0 -e wlan0 -M network -T tun -c 10.1.10.4
./simplemux -i tun1 -e wlan0 -M network -T tun -c 10.1.10.6
./simplemux -i tap3 -e eth1 -M udp -T tap -c 192.168.3.172 -d 2
./simplemux -i tap3 -e eth1 -M tcpserver -T tap -c 192.168.3.172 -d 3 -n 1 -f
./simplemux -i tap3 -e eth1 -M tcpclient -T tap -c 192.168.3.171 -d 2 -n 1 -f
```

# Acknowledgements

This work has been partially financed by the **EU H2020 Wi-5 project** (G.A. no: 644262, see http://www.wi5.eu/ and https://github.com/Wi5), and the Spanish Ministry of Economy and Competitiveness project TIN2015-64770-R, in cooperation with the European Regional Development Fund.

The extensions added to Simplemux, as long as the `.lua` Wireshark dissector, have been done as a part of the **[H2020 FARCROSS project](https://cordis.europa.eu/project/id/864274)**, see [farcross.eu/](https://farcross.eu/). This project has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No 864274.

Jose Saldana (working at CIRCE Foundation), improved it in 2021-2022.

Jose Saldana (working at University of Zaragoza) wrote this program in 2015, published under GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007 Copyright (C) 2007 Free Software Foundation, Inc.

Thanks to Davide Brini for his simpletun.c program. (2010) http://backreference.org/wp-content/uploads/2010/03/simpletun.tar.bz2

This program uses an implementation of ROHC by Didier Barvaux (https://rohc-lib.org/).

# Disclaimer

This program has been written for research purposes, so if you find it useful, I would appreciate that you send a message sharing your experiences, and your improvement suggestions.

DISCLAIMER AND WARNING: this is all work in progress. The code may be ugly, the algorithms may be naive, error checking and input validation are very basic, and of course there can be bugs. If that's not enough, the program has not been thoroughly tested, so it might even fail at the few simple things it should be supposed to do right.

Needless to say, I take no responsibility whatsoever for what the program might do. The program has been written mostly for research purposes, and can be used in the hope that is useful, but everything is to be taken "as is" and without any kind of warranty, implicit or explicit. See the file LICENSE for further details.