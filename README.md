# simplemux

There are some situations in which multiplexing a number of small packets into a bigger one is desirable. For example, a number of small packets can be sent together between a pair of machines if they share a common network path. Thus, the traffic profile can be shifted from small to larger packets, reducing the network overhead and the number of packets per second to be managed by intermediate routers.

Simplemux is a protocol able to encapsulate a number of packets belonging to different protocols into a single packet. It includes the "Protocol" field on each multiplexing header, thus allowing the inclusion of a number of packets belonging to different protocols on a packet of another protocol.

The specification of Simplemux is here: http://datatracker.ietf.org/doc/draft-saldana-tsvwg-simplemux/. It has been proposed to the Transport Area Working Group of the IETF (https://datatracker.ietf.org/wg/tsvwg/documents/)

The size of the multiplexing headers is kept very low (it may be a single byte when multiplexing small packets) in order to reduce the overhead.

This page includes an implementation of Simplemux written in C for Linux. It uses simplemux as the multiplexing protocol, and IP and ROHC as multiplexed protocols.


Simplemux has two tunneling modes, depending on the use of Linux TUN/TAP virtual interfaces:
- **TUN tunneling mode**: IP packets are multiplexed between the two endpoints.
- **TAP tunneling mode**: Ethernet frames are multiplexed between the two endpoints.


Simplemux can run in four modes:
- **Network mode**: the multiplexed packet is sent in an IP datagram using Protocol Number 253 or 254 (according to IANA, these numbers can be used for experimentation and testing ).
- **UDP mode**: the multiplexed packet is sent in an UDP/IP datagram. In this case, the protocol number in the outer IP header is that of UDP (17) and both ends must agree on a UDP port (the implementation uses 55555 or 55557 by default).
- **TCP server mode**: the multiplexed packet is sent in a TCP/IP datagram. In this case, the protocol number in the outer IP header is that of TCP (4) and both ends must agree on a TCP port (the implementation uses 55555 or 55557 by default).
- **TCP client mode**: same as TCP server mode, but it is the TCP client.


Simplemux has two *flavors*:

- **Normal**: it tries to compress the separators as much as possible. For that aim, some single-bit fields are used.
- **Fast**: it sacrifices some compression on behalf or speed. In this case, all the separators are 3-byte long, and all have the same structure.
Simplemux *fast* must be used in TCP *mode*. This is the reason: TCP is a "stream", i.e. it is no longer valid the concept "a set of multiplexed packets goes inside a muxed packet". Now, a TCP packet may carry part of a packet, or 2 or 3 packets. Therefore, the structure of all the headers MUST be the same. The "single protocol bit" does not make sense in this case.


ROCH feedback messages are always sent in IP/UDP packets.

A research paper about Simplemux can be found here: http://diec.unizar.es/~jsaldana/personal/chicago_CIT2015_in_proc.pdf

A presentation about Simplemux can be found here: http://es.slideshare.net/josemariasaldana/simplemux-traffic-optimization


## How to install ROHC and compile Simplemux

In Debian, you will need these packages:
```
sudo apt-get install git
sudo apt-get install build-essential
sudo apt-get install pkgconf
```

Download version 1.7.0 from https://rohc-lib.org/support/download/, and unzip the content in a folder. You can do it with these commands:
```
wget https://rohc-lib.org/download/rohc-1.7.x/1.7.0/rohc-1.7.0.tar.xz --no-check-certificate
tar -xvf rohc-1.7.0.tar.xz
```

Go go the ROHC folder and do this:
```
cd rohc-1.7.0/
./configure --prefix=/usr
make all
make check
sudo make install
cd ..
```

And now, you can download and compile simplemux:
```
~/$ git clone https://github.com/Simplemux/simplemux.git
~/$ cd simplemux
~/simplemux$ gcc -o simplemux -g -Wall $(pkg-config rohc --cflags) simplemux.c $(pkg-config rohc --libs )
```

## Usage examples
```
~/simplemux$ ./simplemux -i tun0 -e wlan0 -M network -T tun -c 10.1.10.4
~/simplemux$ ./simplemux -i tun1 -e wlan0 -M network -T tun -c 10.1.10.6
~/simplemux$ ./simplemux -i tap3 -e eth1 -M udp -T tap -c 192.168.3.172 -d 2
~/simplemux$ ./simplemux -i tap3 -e eth1 -M tcpserver -T tap -c 192.168.3.172 -d 3 -n 1 -f
~/simplemux$ ./simplemux -i tap3 -e eth1 -M tcpclient -T tap -c 192.168.3.171 -d 2 -n 1 -f
```

## Example: running Simplemux in tun tunneling mode (`-T tun` option), i.e. send tunneled IP packets

To create a tun device, run these commands as root:
```
$ sudo ip tuntap add dev tun0 mode tun user root
$ sudo ip link set tun0 up
```

To test, you can add an IP address to `tun0`:
```
$ sudo ip addr add 192.168.100.1/24 dev tun0
$ route -nn
```

Do the same in the other machine, but using another IP address, e.g. `192.168.100.2`

### Run Simplemux in tun tunneling mode (`-T tun` option) and Network mode (`-M network`):
Run this command at the machine with IP address `192.168.129.134`
```
~/simplemux$ sudo ./simplemux -i tun0 -e ens33 -M network -T tun -c 192.168.129.129 -d 2
```

Run this command at the machine with IP address `192.168.129.129`
```
~/simplemux$ sudo ./simplemux -i tun0 -e ens33 -M network -T tun -c 192.168.129.134 -d 2
```

### Run Simplemux in tun tunneling mode (`-T tun` option) and UDP mode (`-M UDP`):
Run this command at the machine with IP address `192.168.129.134`
```
~/simplemux$ sudo ./simplemux -i tun0 -e ens33 -M UDP -T tun -c 192.168.129.129 -d 2
```

Run this command at the machine with IP address `192.168.129.129`
```
~/simplemux$ sudo ./simplemux -i tun0 -e ens33 -M UDP -T tun -c 192.168.129.134 -d 2
```

### Run Simplemux in tun tunneling mode (`-T tun` option), TCP mode (`-M tcpserver` or `-M tcpclient`) and `fast` flavor (`-f`):
First, run the server at the machine with IP address `192.168.129.134`
```
~/simplemux$ sudo ./simplemux -i tun0 -e ens33 -M tcpserver -T tun -c 192.168.129.129 -d 2
```

Then, run the client at the machine with IP address `192.168.129.129`
```
~/simplemux$ sudo ./simplemux -i tun0 -e ens33 -M tcpclient -T tun -c 192.168.129.134 -d 2
```

In these cases, ping should work, i.e. it should send traffic to the other machine
```
~/simplemux$ ping 192.168.100.2
PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
64 bytes from 192.168.100.2: icmp_seq=1 ttl=64 time=2.83 ms
64 bytes from 192.168.100.2: icmp_seq=2 ttl=64 time=2.24 ms
64 bytes from 192.168.100.2: icmp_seq=3 ttl=64 time=2.64 ms
64 bytes from 192.168.100.2: icmp_seq=4 ttl=64 time=3.93 ms
64 bytes from 192.168.100.2: icmp_seq=5 ttl=64 time=1.09 ms
```

If you use Network mode (`-M network`) you should see this:
~/simplemux$ tcpdump -i ens33 -nn
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens33, link-type EN10MB (Ethernet), capture size 262144 bytes
07:48:30.755359 IP 192.168.129.133 > 192.168.129.129:  ip-proto-253 87
07:48:30.756616 IP 192.168.129.129 > 192.168.129.133:  ip-proto-253 87
07:48:31.760115 IP 192.168.129.133 > 192.168.129.129:  ip-proto-253 87
07:48:31.761670 IP 192.168.129.129 > 192.168.129.133:  ip-proto-253 87


## Example: running Simplemux in tap tunneling mode, i.e. send tunneled frames (including eth header)

To create a tap, run these commands as root:
```
~/simplemux$ sudo ip tuntap add dev tap0 mode tap user root
~/simplemux$ sudo ip link set tap0 up
```

Note: ROHC cannot be used in TAP mode (use `-r 0` option).

Run Simplemux in tap tunneling mode (`-T tap` option) and UDP mode:
```
~/simplemux$ sudo ./simplemux -i tap0 -e ens33 -M udp -T tap -c 192.168.129.129 -d 2 -r 0
```

Create a bridge connecting `tap0` and the ethernet card, so the frames will be sent to the other side of the tunnel:
```
~/simplemux$ sudo ip link add br0 type bridge
~/simplemux$ sudo ip link set br0 up
~/simplemux$ sudo ip link set tap0 master br0
~/simplemux$ sudo ip link set ens33 master br0
```

ACKNOWLEDGEMENTS
----------------
This work has been partially financed by the **EU H2020 Wi-5 project** (G.A. no: 644262, see http://www.wi5.eu/ and https://github.com/Wi5), and the Spanish Ministry of Economy and Competitiveness project TIN2015-64770-R, in cooperation with the European Regional Development Fund.

The extensions added to Simplemux, as long as the `.lua` Wireshark dissector, have been done as a part of the **[H2020 FARCROSS project](https://cordis.europa.eu/project/id/864274)**, see [farcross.eu/](https://farcross.eu/). This project has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No 864274.
