# Simplemux - Example scenarios

[[_TOC_]]

## Scenario 1 - Two raspberries sending Ethernet frames

- Tunnel mode: `tap`
- Mode: `network`, `UDP` or `TCP`
- Flavor: `normal`, `fast` or `blast`

In this example scenario, two Raspberries have been used as the multiplexer and the demultiplexer. Using **tap tunnel mode**, whole Ethernet frames are sent between two distant networks.

<img src="images/scenario_two-raspberries.png" alt="Scenario with two raspberries" width="600"/>

Only the frames tagged as VLAN=`3` will be sent through the Simplemux tunnel.

These are the protocols employed:
- Multiplexed protocol: Ethernet.
- Multiplexing protocol: Simplemux.
- Tunneling protocol: IP, UDP/IP or TCP/IP.

Raspberry 1
- `eth0`: `192.168.2.171`
- `eth1`: `192.168.3.171`
- `br3`: `192.168.33.171`

Raspberry 2
- `eth0`: `192.168.2.172`
- `eth1`: `192.168.3.172`
- `br3`: `192.168.33.172`

```
          +--------------------------+
          |                          |
       +----+                      +----+      
+------|eth1|------+        +------|eth1|------+
|      +----+      |        |      +----+      |
|         |        |        |         |        |
|    +---------+   |        |    +---------+   |
|    |simplemux|   |        |    |simplemux|   |
|    +---------+   |        |    +---------+   |
|         |        |        |         |        |
|    +---------+   |        |    +---------+   |
|    |  tap3   |   |        |    |  tap3   |   |
|    +---------+   |        |    +---------+   |
|         |        |        |         |        |
|    +---------+   |        |    +---------+   |
|    |   br3   |   |        |    |   br3   |   |
|    +---------+   |        |    +---------+   |
|         |        |        |         |        |
|   +------+       |        |   +------+       | 
|   |eth0.3|       |        |   |eth0.3|       |
|   +------+       |        |   +------+       |
|         |        |        |         |        |
|      +----+      |        |      +----+      |
+------|eth0|------+        +------|eth0|------+
       +----+                      +----+      

     Raspberry 1                Raspberry 2
```

### Prepare the two devices

With this script, you create the devices in Raspberry 1:

<details close>
<summary>Script Raspberry 1</summary>

```
# raspberry 1
# add the interface eth0.3, part of VLAN 3
ip link add link eth0 name eth0.3 type vlan id 3
# add the interface tap3
ip tuntap add dev tap3 mode tap user root
# set the interface up
ip link set tap3 up
# add a bridge where we will put eth0.3 and tap3
ip link add br3 type bridge
# add tap3 interface to the bridge
ip link set tap3 master br3
# add an IP address to tap3 (probably not needed)
ifconfig tap3 10.0.3.171 netmask 255.255.255.0
# add an IP address to br3 (useful for testing that the setup is correct)
ifconfig br3 192.168.33.171
# add eth0.3 to the bridge
ip link set eth0.3 master br3
# set the bridge up
ip link set br3 up
```
</details>

With this script you can create the devices in Raspberry 2:

<details close>
<summary>Script Raspberry 2</summary>

```
# raspberry 2
# add the interface eth0.3, part of VLAN 3
ip link add link eth0 name eth0.3 type vlan id 3
# add the interface tap3
ip tuntap add dev tap3 mode tap user root
# set the interface up
ip link set tap3 up
# add a bridge where we will put eth0.3 and tap3
ip link add br3 type bridge
# add tap3 interface to the bridge
ip link set tap3 master br3
# add an IP address to tap3 (probably not needed)
ifconfig tap3 10.0.3.172 netmask 255.255.255.0
# add an IP address to br3 (useful for testing that the setup is correct)
ifconfig br3 192.168.33.172
# add eth0.3 to the bridge
ip link set eth0.3 master br3
# set the bridge up
ip link set br3 up
```
</details>

### Run Simplemux

#### Raspberry 1

Run `Simplemux` to create a tunnel to the other side.

- using *network mode* (in the example, *blast* flavor is used with a period of 15 ms):
```
$ ./simplemux -i tap3 -e eth1 -M udp -T tap -c 192.168.3.172 -d 2 -b -P 15000
```

- using UDP (in the example, *normal* flavor is used):
```
$ ./simplemux -i tap3 -e eth1 -M udp -T tap -c 192.168.3.172 -d 2
```

- using TCP server (in the example, *fast* flavor is used):
```
./simplemux/simplemux -i tap3 -e eth1 -M tcpserver -T tap -c 192.168.3.172 -d 3 -n 1 -f
```

#### Raspberry 2

Run `Simplemux` to create a tunnel to the other side.

- using *network mode* (in the example, *blast* flavor is used with a period of 15 ms):
```
$ ./simplemux -i tap3 -e eth1 -M udp -T tap -c 192.168.3.171 -d 2 -b -P 15000
```

- using UDP (in the example, *normal* flavor is used):
```
$ ./simplemux -i tap3 -e eth1 -M udp -T tap -c 192.168.3.171 -d 2
```

- using TCP server (in the example, *fast* flavor is used):
```
./simplemux/simplemux -i tap3 -e eth1 -M tcpserver -T tap -c 192.168.3.171 -d 3 -n 1 -f
```

You can now ping from Raspberry 1 to `192.168.33.172`, and you will see if the tunnel works.


## Scenario 2 - Sending IP packets between VMs

- Tunnel mode: `tun`
- Mode: `UDP`
- Flavor: `normal`

This has been tested using three Debian Virtual Machines inside a Windows PC.

This is the setup:

```
                      +------+                               +--------+         +---------+
                      |switch|                               | router |---------| x.y.z.t |
                      +------+                               +--------+         +---------+
                      /      \                               /        \         destination
                     /        \                             /          \
       +-------------+        +-------------+  +-------------+        +-------------+
   +---|192.168.200.6|-+    +-|192.168.200.5|--| 192.168.0.5 |-+    +-|192.168.137.4|---+
   |   |eth0         | |    | |eth1         |  |eth0         | |    | |eth0         |   |
   |   +-------------+ |    | +-------------+  +-------------+ |    | +-------------+   |
   |                   |    |                      |           |    |     |             |
   |                   |    |                   simplemux      |    |   simplemux       |
   |                   |    |                      |           |    |     |             |
   |                   |    |           +-------------+        |    | +-------------+   |
   |                   |    |           |192.168.100.5|        |    | |192.168.100.4|   |
   |                   |    |           |tun0         |        |    | |tun0         |   |
   |                   |    |           +-------------+        |    | +-------------+   |
   |                   |    |                                  |    |                   |
   |     Machine 6     |    |          Machine 5 (router)      |    |     Machine 4     |
   +-------------------+    +----------------------------------+    +-------------------+
```

Machine 6 is the source. Machine 5 and Machine 4 are the two optimizers. The machine `x.y.z.t` is the destination.

### Create a tun interface in machine 4
```
$ ip tuntap add dev tun0 mode tun user root
$ ip link set tun0 up
```
In other cases, e.g. OpenWRT, you can run `$ ifconfig tun0 up`.

If you want to add an IP address to the `tun0` interface, use:
```
$ ip addr add 192.168.100.4/24 dev tun0
```
If you do not need an IP address, you can omit the previous command.

For removing the interface use `$ ip tuntap del dev tun0 mode tun`.

Note: `$ openvpn --mktun --dev tun0 --user root` will work in OpenWrt and also in other Linux distributions). `Openvpn` is used to create and destroy tun/tap devices. In Debian you can install it this way: `$ apt-get install openvpn`.

In OpenWRT you will not be able to run `$ ip tuntap`, so you should install openvpn with: `$ opkg install openvpn-nossl` (run `$ opkg update` before).

### Create a tun interface in machine 5
```
$ ip tuntap add dev tun0 mode tun user root
```
Note: `$ openvpn --mktun --dev tun0 --user root` will also work.

```
$ ip link set tun0 up
$ ip addr add 192.168.100.5/24 dev tun0
```

### Establish the simplemux tunnel between Machine 4 and Machine 5

In Machine4:
```
$ ./simplemux -i tun0 -e eth0 -M udp -T tun -c 192.168.0.5
```

In Machine5:
```
$ ./simplemux -i tun0 -e eth0 –M udp -T tun -c 192.168.137.4
```
 
### Test the tunnel

Now you can ping from Machine 5 or Machine 6, to Machine 4:
```
$ ping 192.168.100.4
```

The ping arrives to the `tun0` interface of Machine 5, goes to Machine 4 through the tunnel and is returned to Machine 6 through the tunnel.


### Steer traffic from Machine 6 to server `x.y.z.t` through the tunnel

The idea of Simplemux is that it does not run at endpoints, but on some “optimizing” machines in the network. Therefore, you have to define policies to steer the flows of interest, in order to make them go through the _tun_ interface of the ingress (Machine 5). This can be done with `ip rule` and `iptables`.

In Machine 5, add a rule that makes the kernel route packets marked with `2` through table `3`:
```
$ ip rule add fwmark 2 table 3
```

In Machine 5, add a new route for table `3`:
```
$ ip route add default dev tun0 table 3
$ ip route flush cache
```
Note: If you have set an IP address in the `tun0` interface, this command should also work:
```
$ ip route add default via 192.168.100.5 table 3
```

If you show the routes of table `3`, you will see this:
```
$ ip route show table 3
default via 192.168.100.5 dev tun0
```

And now you can use `iptables` in order to mark certain packets as `2` if they have a certain destination IP, or a port number. Examples of commands to add iptables entries:

- All packets with destination IP address `x.y.z.t`.
```
iptables -t mangle -A PREROUTING -p udp -d x.y.z.t -j MARK --set-mark 2
```

- All packets with destination UDP port `8999`:
```
iptables -t mangle -A PREROUTING -p udp --dport 8999 -j MARK --set-mark 2
```

- All packets with destination TCP port `44172`:
```
iptables -t mangle -A PREROUTING -p tcp --dport 44172 -j MARK --set-mark 2
```

Remove the table rule:
```
iptables -t mangle -D PREROUTING -p tcp --dport 44172 -j MARK --set-mark 2
```

Show the table:
```
iptables -t mangle –L
```


## Scenario 3 - Simplemux between two Virtual Machines in the same computer

Run Simplemux between two VMs with IP addresses `192.168.129.131` and `192.168.129.132`.


```
                        +--------+
                        | switch |
                        +--------+
                        /        \
                       /          \
       +---------------+          +---------------+  
   +---|192.168.129.131|-+      +-|192.168.129.132|---+
   |   |ens33          | |      | |ens33          |   |
   |   +---------------+ |      | +---------------+   |  
   |        |            |      |          |          |
   |    simplemux        |      |      simplemux      |
   |        |            |      |          |          |
   |   +-------------+   |      |  +-------------+    |
   |   |192.168.100.1|   |      |  |192.168.100.2|    |
   |   |tun0         |   |      |  |tun0         |    |
   |   +-------------+   |      |  +-------------+    |
   |                     |      |                     |
   |     Machine 1       |      |      Machine 2      |
   +---------------------+      +---------------------+
```

### tun mode

To create a *tun* interface, run these commands as `root` (to test, you can add an IP address to `tun0`)

```
sudo ip tuntap add dev tun0 mode tun user root
sudo ip link set tun0 up
sudo ip addr add 192.168.100.1/24 dev tun0
sudo route -nn
```

Do the same in the other machine, but using `192.168.100.2`:

```
sudo ip tuntap add dev tun0 mode tun user root
sudo ip link set tun0 up
sudo ip addr add 192.168.100.2/24 dev tun0
sudo route -nn
```

Run Simplemux in `tun` tunnel mode (`-T tun` option):

In the machine with IP address `192.168.129.131` you can run Simplemux in one of these ways:
```
$ ./simplemux -i tun0 -e ens33 -M udp -T tun -c 192.168.129.132 -d 2
$ ./simplemux -i tun0 -e ens33 -M network -T tun -c 192.168.129.132 -d 2
$ ./simplemux -i tun0 -e ens33 -M tcpserver -f -T tun -c 192.168.129.132 -d 2
```

In the machine with IP address `192.168.129.132` you can run Simplemux in one of these ways:
```
$ ./simplemux -i tun0 -e ens33 -M udp -T tun -c 192.168.129.131 -d 2
$ ./simplemux -i tun0 -e ens33 -M network -T tun -c 192.168.129.131 -d 2
$ ./simplemux -i tun0 -e ens33 -M tcpclient -f -T tun -c 192.168.129.131 -d 2
```

Test if Simplemux is working using this command in Machine 1:
```
ping 192.168.100.2
```

If the ping works, it means it sends traffic to the other machine, so Simplemux is working.


### tap mode

Note: RoHC cannot be used in `tap` tunnel mode (use `-r 0` option).

To create a *tap* interface , run these commands as `root`:

```
sudo ip tuntap add dev tap0 mode tap user root
sudo ip link set tap0 up
sudo ip addr add 192.168.200.1/24 dev tap0
```

Do the same in the other machine, but using `192.168.100.2`:
```
sudo ip tuntap add dev tap0 mode tap user root
sudo ip link set tap0 up
sudo ip addr add 192.168.200.2/24 dev tap0
```


Run Simplemux in tap mode (`-T tap` option):

In the machine with IP address `192.168.129.131` you can run Simplemux in one of these ways:
```
$ ./simplemux -i tap0 -e ens33 -M udp -T tap -c 192.168.129.132 -d 2
$ ./simplemux -i tap0 -e ens33 -M network -T tap -c 192.168.129.132 -d 2
$ ./simplemux -i tap0 -e ens33 -M tcpserver -f -T tap -c 192.168.129.132 -d 2
```

In the machine with IP address `192.168.129.132` you can run Simplemux in one of these ways:
```
$ ./simplemux -i tap0 -e ens33 -M udp -T tap -c 192.168.129.131 -d 2
$ ./simplemux -i tap0 -e ens33 -M network -T tap -c 192.168.129.131 -d 2
$ ./simplemux -i tap0 -e ens33 -M tcpclient -f -T tap -c 192.168.129.131 -d 2
```

Test if Simplemux is working using this command in Machine 1:
```
ping 192.168.200.2
```
If the ping works, it means it sends traffic to the other machine, so Simplemux is working.


## Scenario 4 - Simplemux between namespaces in a single Linux machine. Tun mode

With network namespaces, you can have different and separate instances of network interfaces and routing tables that operate independent of each other.

More info:

https://medium.com/@bjnandi/linux-network-namespace-with-bridge-d68831d5e8a1

https://blogs.igalia.com/dpino/2016/04/10/network-namespaces/

An interface can only be assigned to one namespace at a time. If the root namespace owns `eth0`, which provides access to the external world, only programs within the root namespace could reach the Internet .

The solution is to communicate a namespace with the root namespace via a *veth* pair. A *veth* pair works like a patch cable, connecting two sides. It consists of two virtual interfaces:
- one of them is assigned to the root network namespace
- the other lives within a network namespace.

Each namespace has two interfaces, which are connected like a pipe. Virtual Ethernet interfaces always come in pairs, and they are connected like a tube: whatever comes in one veth interface will come out the other peer veth interface. You can then use bridges to connect them.


### Scenario to be built

```
                   +------------+
                   |br10        |
                   |192.168.1.11|
                   +------------+
                     /        \
                    /          \
       +-------------+              +------------+
       |brveth0      |              |brveth1     |
   +---+-------------+---+      +---+------------+---+
   |   |192.168.1.20 |   |      |   |192.168.1.21|   |
   |   |veth0        |   |      |   |veth1       |   |
   |   +-------------+   |      |   +------------+   |  
   |          |          |      |         |          |
   |      simplemux      |      |     simplemux      |
   |          |          |      |         |          |
   |   +-------------+   |      |   +-------------+  |
   |   |192.168.100.1|   |      |   |192.168.100.2|  |
   |   |tun0         |   |      |   |tun1         |  |
   |   +-------------+   |      |   +-------------+  |
   |                     |      |                    |
   |     ns0             |      |      ns1           |
   +---------------------+      +--------------------+
```

### Add the namespaces

Add two network namespaces `ns0` and `ns1`:
```
ip netns add ns0
ip netns add ns1
```

You can now see the global namespace list:
```
$ ip netns list
ns1 (id: 1)
ns0 (id: 0)
```

### Create the linked interfaces

Create two linked interfaces `veth0` and `brveth0`, and set up `brveth0`:
```
ip link add veth0 type veth peer name brveth0 
ip link set brveth0 up
```

Create two linked interfaces `veth1` and `brveth1`, and set up `brveth1`:
```
ip link add veth1 type veth peer name brveth1
ip link set brveth1 up
```

### Assign the linked interfaces to each namespace

Assign `veth0` to `ns0` and `veth1` to `ns1`:
```
ip link set veth0 netns ns0
ip link set veth1 netns ns1
```

### Add IP addresses to the interfaces

Inside `ns0`, add an IP address to `veth0`, set it up, and also set up the local interface `lo`:
```
ip netns exec ns0 ip addr add 192.168.1.20/24 dev veth0
ip netns exec ns0 ip link set veth0 up
ip netns exec ns0 ip link set lo up
```

Inside `ns1`, add the IP address to `veth1`, set it up, and also set up the local interface `lo`:
```
ip netns exec ns1    ip addr add 192.168.1.21/24 dev veth1
ip netns exec ns1    ip link set veth1 up
ip netns exec ns1    ip link set lo up
```

### Add the bridge and connect the linked interfaces to it

Add a bridge `br10` and set it up:
```
ip link add br10 type bridge 
ip link set br10 up
```

Add an IP address to the bridge (`brd` is for also adding broadcast). (Note: Another option for creating the bridge `br0`: `brctl addbr br0`):
```
ip addr add 192.168.1.11/24 brd + dev br10
```
Note: this allows you to communicate `ns0` and `ns1` with the global namespace.


### Connect the interfaces to the bridge

Associate `brveth0` and `brveth1` to the bridge `br10`:
``` 
ip link set brveth0 master br10
ip link set brveth1 master br10
```

List the bridges (you need to install `bridge-utils` package using `$ sudo apt install bridge-utils`):
```
$ brctl show
bridge name     bridge id               STP enabled     interfaces
br10            8000.128812c192fd       no              brveth0
                                                        brveth1
```

### First result: connection between the namespaces

As expected, I can ping from `ns1` to the interface in `ns0`:
```
$ ip netns exec ns1 ping -c 3  192.168.1.20
PING 192.168.1.20 (192.168.1.20) 56(84) bytes of data.
64 bytes from 192.168.1.20: icmp_seq=1 ttl=64 time=0.099 ms
64 bytes from 192.168.1.20: icmp_seq=2 ttl=64 time=0.189 ms
```

Note: `eth0` is not connected with the bridge `br10`, so traffic cannot go outside the machine.


### Add the *tun* devices

In `ns0`, add `tun0`:
```
ip netns exec ns0 ip tuntap add dev tun0 mode tun user root
ip netns exec ns0 ip link set tun0 up
ip netns exec ns0 ip addr add 192.168.100.1/24 dev tun0
```

In `ns1`, add `tun1`:
```
ip netns exec ns1 ip tuntap add dev tun1 mode tun user root
ip netns exec ns1 ip link set tun1 up
ip netns exec ns1 ip addr add 192.168.100.2/24 dev tun1
```

### Run Simplemux

Simplemux in `ns0`:
```
ip netns exec ns0 ./simplemux -i tun0 -e veth0 -M udp -T tun -c 192.168.1.21 -d 2
```

Simplemux in `ns1`:
```
ip netns exec ns1 ./simplemux -i tun1 -e veth1 -M udp -T tun -c 192.168.1.20 -d 2
```

And now, you can ping between `tun0` and `tun1`:
```
ip netns exec ns0 ping 192.168.100.2
```

### All the commands together

<details close>
<summary>All the commands</summary>

```
ip netns add ns0
ip netns add ns1
ip link add veth0 type veth peer name brveth0 
ip link set brveth0 up
ip link add veth1 type veth peer name brveth1
ip link set brveth1 up
ip link set veth0 netns ns0
ip link set veth1 netns ns1
ip netns exec ns0 ip addr add 192.168.1.20/24 dev veth0
ip netns exec ns0 ip link set veth0 up
ip netns exec ns0 ip link set lo up
ip netns exec ns1 ip addr add 192.168.1.21/24 dev veth1
ip netns exec ns1 ip link set veth1 up
ip netns exec ns1 ip link set lo up
ip link add br10 type bridge 
ip link set br10 up
ip addr add 192.168.1.11/24 brd + dev br10
ip link set brveth0 master br10
ip link set brveth1 master br10
ip netns exec ns0 ip tuntap add dev tun0 mode tun user root
ip netns exec ns0 ip link set tun0 up
ip netns exec ns0 ip addr add 192.168.100.1/24 dev tun0
ip netns exec ns1 ip tuntap add dev tun1 mode tun user root
ip netns exec ns1 ip link set tun1 up
ip netns exec ns1 ip addr add 192.168.100.2/24 dev tun1
ip netns exec ns0 ./simplemux -i tun0 -e veth0 -M udp -T tun -c 192.168.1.21 -d 2
ip netns exec ns1 ./simplemux -i tun1 -e veth1 -M udp -T tun -c 192.168.1.20 -d 2
ip netns exec ns0 ping 192.168.100.2
```
</details>


Another option to send the traffic (UDP packets with 100-byte payload):
```
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 100
```

### Compress a number of flows in this scenario

We are going to multiplex a number of flows, and obtain the throughput.

We create a script `scriptNumberFlows.sh` with this content:
```
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9001 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9002 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9003 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9004 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9005 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9006 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9007 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9008 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9009 &
ip netns exec ns0 iperf -c 192.168.100.2 -u -l 20 -p 9010
```

Prepare the Simplemux ingress and egress:
```
$ ip netns exec ns0 ./simplemux/simplemux -i tun0 -e veth0 -M network -T tun -c 192.168.1.21 -d 1 -r 2 -f -P 100000 -l logIngress.txt
$ ip netns exec ns1 ./simplemux/simplemux -i tun1 -e veth1 -M network -T tun -c 192.168.1.20 -d 1 -r 2 -f
```

And run `$ scriptNumberFlows.sh`

#### Obtain the graph with the input throughput and pps, with a tick of 1 second:
```
$ perl ./simplemux/perl/simplemux_throughput_pps.pl logIngress.txt 1000000 rec native all all
tick_end_time(us)	throughput(bps)	packets_per_second
1000000	79872	208
2000000	116736	304
3000000	61440	160
4000000	68352	178
5000000	63360	165
6000000	65664	171
7000000	47616	124
8000000	51840	135
9000000	56064	146
10000000	55680	145
11000000	203904	531
12000000	12672	33
```

#### Obtain the graph with the output throughput and pps, with a tick of 1 second:
```
$ perl ./simplemux/perl/simplemux_throughput_pps.pl logIngress.txt 1000000 sent muxed all all
tick_end_time(us)	throughput(bps)	packets_per_second
1000000	37120	4
2000000	71448	6
3000000	35504	3
4000000	47368	4
5000000	35680	3
6000000	47448	4
7000000	23736	2
8000000	35616	3
9000000	35688	3
10000000	35536	3
11000000	133896	13
12000000	8048	5
```
As it can be observed, in the first second we pass from 79872 to 37120 bps (46%, i.e. reduction by a factor of 2.15). The number of packets passes from 208 to 4 (reduction by a factor of 52, i.e. each multiplexed packet contains 52 original ones).


#### Obtain the multiplexing delay

```
$ perl ./simplemux/perl/simplemux_multiplexing_delay.pl logIngress.txt output.txt
total native packets:	2314
Average multiplexing delay:	127179.163785653 us
stdev of the multiplexing delay:	104014.990648023 us
```

See the delay added to each packet:
```
$ cat output.txt 
packet_id	multiplexing_delay(us)
1	8049
2	5560
3	3970
4	361017
5	360576
6	360342
7	360144
8	358944
9	348858
10	346334
11	333759
12	330156
13	324434
(...)
```

## Scenario 5 - Simplemux between namespaces in a single Linux machine. Tap mode

With network namespaces, you can have different and separate instances of network interfaces and routing tables that operate independent of each other.

More info:

https://medium.com/@bjnandi/linux-network-namespace-with-bridge-d68831d5e8a1

https://blogs.igalia.com/dpino/2016/04/10/network-namespaces/

An interface can only be assigned to one namespace at a time. If the root namespace owns `eth0`, which provides access to the external world, only programs within the root namespace could reach the Internet .

The solution is to communicate a namespace with the root namespace via a *veth* pair. A *veth* pair works like a patch cable, connecting two sides. It consists of two virtual interfaces:
- one of them is assigned to the root network namespace
- the other lives within a network namespace.

Each namespace has two interfaces, which are connected like a pipe. Virtual Ethernet interfaces always come in pairs, and they are connected like a tube: whatever comes in one veth interface will come out the other peer veth interface. You can then use bridges to connect them.


### Scenario to be built

```
                   +------------+
                   |br10        |
                   |192.168.1.11|
                   +------------+
                     /        \
                    /          \
       +-------------+              +------------+
       |brveth0      |              |brveth1     |
   +---+-------------+---+      +---+------------+---+
   |   |192.168.1.20 |   |      |   |192.168.1.21|   |
   |   |veth0        |   |      |   |veth1       |   |
   |   +-------------+   |      |   +------------+   |  
   |          |          |      |         |          |
   |      simplemux      |      |     simplemux      |
   |          |          |      |         |          |
   |   +-------------+   |      |   +-------------+  |
   |   |192.168.200.1|   |      |   |192.168.200.2|  |
   |   |tap0         |   |      |   |tap1         |  |
   |   +-------------+   |      |   +-------------+  |
   |                     |      |                    |
   |     ns0             |      |      ns1           |
   +---------------------+      +--------------------+
```

### Add the namespaces

Add two network namespaces `ns0` and `ns1`:
```
ip netns add ns0
ip netns add ns1
```

You can now see the global namespace list:
```
$ ip netns list
ns1 (id: 1)
ns0 (id: 0)
```

### Create the linked interfaces

Create two linked interfaces `veth0` and `brveth0`, and set up `brveth0`:
```
ip link add veth0 type veth peer name brveth0 
ip link set brveth0 up
```

Create two linked interfaces `veth1` and `brveth1`, and set up `brveth1`:
```
ip link add veth1 type veth peer name brveth1
ip link set brveth1 up
```

### Assign the linked interfaces to each namespace

Assign `veth0` to `ns0` and `veth1` to `ns1`:
```
ip link set veth0 netns ns0
ip link set veth1 netns ns1
```

### Add IP addresses to the interfaces

Inside `ns0`, add an IP address to `veth0`, set it up, and also set up the local interface `lo`:
```
ip netns exec ns0 ip addr add 192.168.1.20/24 dev veth0
ip netns exec ns0 ip link set veth0 up
ip netns exec ns0 ip link set lo up
```

Inside `ns1`, add the IP address to `veth1`, set it up, and also set up the local interface `lo`:
```
ip netns exec ns1    ip addr add 192.168.1.21/24 dev veth1
ip netns exec ns1    ip link set veth1 up
ip netns exec ns1    ip link set lo up
```

### Add the bridge and connect the linked interfaces to it

Add a bridge `br10` and set it up:
```
ip link add br10 type bridge 
ip link set br10 up
```

Add an IP address to the bridge (`brd` is for also adding broadcast). (Note: Another option for creating the bridge `br0`: `brctl addbr br0`):
```
ip addr add 192.168.1.11/24 brd + dev br10
```
Note: this allows you to communicate `ns0` and `ns1` with the global namespace.


### Connect the interfaces to the bridge

Associate `brveth0` and `brveth1` to the bridge `br10`:
``` 
ip link set brveth0 master br10
ip link set brveth1 master br10
```

List the bridges (you need to install `bridge-utils` package using `$ sudo apt install bridge-utils`):
```
$ brctl show
bridge name     bridge id               STP enabled     interfaces
br10            8000.128812c192fd       no              brveth0
                                                        brveth1
```

### First result: connection between the namespaces

As expected, I can ping from `ns1` to the interface in `ns0`:
```
$ ip netns exec ns1 ping -c 3  192.168.1.20
PING 192.168.1.20 (192.168.1.20) 56(84) bytes of data.
64 bytes from 192.168.1.20: icmp_seq=1 ttl=64 time=0.099 ms
64 bytes from 192.168.1.20: icmp_seq=2 ttl=64 time=0.189 ms
```

Note: `eth0` is not connected with the bridge `br10`, so traffic cannot go outside the machine.


### Add the *tap* devices

In `ns0`, add `tun0`:
```
ip netns exec ns0 ip tuntap add dev tap0 mode tun user root
ip netns exec ns0 ip link set tap0 up
ip netns exec ns0 ip addr add 192.168.100.1/24 dev tap0
```

In `ns1`, add `tun1`:
```
ip netns exec ns1 ip tuntap add dev tap1 mode tap user root
ip netns exec ns1 ip link set tap1 up
ip netns exec ns1 ip addr add 192.168.100.2/24 dev tap1
```

### Run Simplemux

Simplemux in `ns0`:
```
ip netns exec ns0 ./simplemux -i tap0 -e veth0 -M udp -T tap -c 192.168.1.21 -d 2
```

Simplemux in `ns1`:
```
ip netns exec ns1 ./simplemux -i tap1 -e veth1 -M udp -T tap -c 192.168.1.20 -d 2
```

And now, you can ping between `tap0` and `tap1`:
```
ip netns exec ns0 ping 192.168.200.2
```

### All the commands together


<details close>
<summary>All the commands</summary>

```
ip netns add ns0
ip netns add ns1
ip link add veth0 type veth peer name brveth0 
ip link set brveth0 up
ip link add veth1 type veth peer name brveth1
ip link set brveth1 up
ip link set veth0 netns ns0
ip link set veth1 netns ns1
ip netns exec ns0 ip addr add 192.168.1.20/24 dev veth0
ip netns exec ns0 ip link set veth0 up
ip netns exec ns0 ip link set lo up
ip netns exec ns1 ip addr add 192.168.1.21/24 dev veth1
ip netns exec ns1 ip link set veth1 up
ip netns exec ns1 ip link set lo up
ip link add br10 type bridge 
ip link set br10 up
ip addr add 192.168.1.11/24 brd + dev br10
ip link set brveth0 master br10
ip link set brveth1 master br10
# add tap devices and run Simplemux
ip netns exec ns0 ip tuntap add dev tap0 mode tap user root
ip netns exec ns0 ip link set tap0 up
ip netns exec ns0 ip addr add 192.168.200.1/24 dev tap0
ip netns exec ns1 ip tuntap add dev tap1 mode tap user root
ip netns exec ns1 ip link set tap1 up
ip netns exec ns1 ip addr add 192.168.200.2/24 dev tap1
ip netns exec ns0 ./simplemux -i tap0 -e veth0 -M udp -T tap -c 192.168.1.21 -d 2
ip netns exec ns1 ./simplemux -i tap1 -e veth1 -M udp -T tap -c 192.168.1.20 -d 2
ip netns exec ns0 ping 192.168.200.2
```
</details>

Another option to send the traffic (UDP packets with 100-byte payload):
```
ip netns exec ns0 iperf -c 192.168.200.2 -u -l 100
```