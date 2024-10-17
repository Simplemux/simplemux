# Simplemux - Example scenarios

[[_TOC_]]

## Scenario 1 - Two raspberries sending Ethernet frames

- Tunnel mode: `tap`
- Mode: `network`, `UDP` or `TCP`
- Flavor: `normal`, `fast` or `blast`

In this example scenario, two Raspberries have been used as the multiplexer and the demultiplexer. Using **tap tunnel mode**, whole Ethernet frames are sent between two distant networks.

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

With this script you can create the devices in Raspberry 2:
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


You can now ping from Raspberry 1 to 192.168.33.172, and you will see if the tunnel works.


## Scenario 2: sending IP packets between VMs

- Tunnel mode: `tun`
- Mode: `UDP`
- Flavor: `normal`

This has been tested using three Debian Virtual Machines inside a Windows PC.

This is the setup:
FIXME: Add image here
```
                      +------+                             +--------+
                      |switch|                             | router |
                      +------+                             +--------+
                      /      \                             /        \
                     /        \                           /          \
       +-------------+       +-------------+ +-------------+        +-------------+
   +---|192.168.200.6|-+   +-|192.168.200.5|-| 192.168.0.5 |-+    +-|192.168.137.4|---+
   |   |eth0         | |   | |eth1         | |eth0         | |    | |eth0         |   |
   |   +-------------+ |   | +-------------+ +-------------+ |    | +-------------+   |
   |                   |   |                     |           |    |     |             |
   |                   |   |                  simplemux      |    |   simplemux       |
   |                   |   |                     |           |    |     |             |
   |                   |   |          +-------------+        |    | +-------------+   |
   |                   |   |          |192.168.100.5|        |    | |192.168.100.4|   |
   |                   |   |          |tun0         |        |    | |tun0         |   |
   |                   |   |          +-------------+        |    | +-------------+   |
   |                   |   |                                 |    |                   |
   |     Machine 6     |   |          Machine 5 (router)     |    |     Machine 4     |
   +-------------------+   +---------------------------------+    +-------------------+
```

Machine 6 is the source. Machine 5 and Machine 4 are the two optimizers. Server x.y.z.t is the destination.

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

For removing the interface use `ip tuntap del dev tun0 mode tun`.

Note: `$ openvpn --mktun --dev tun0 --user root` will work in OpenWrt and also in other Linux distributions). `Openvpn` is used to create and destroy tun/tap devices. In Debian you can install it this way: `$ apt-get install openvpn`.

In OpenWRT you will not be able to run `$ ip tuntap`, so you should install openvpn with: `$ opkg install openvpn-nossl` (do `opkg update` before).

### Create a tun interface in machine 5
```
$ ip tuntap add dev tun0 mode tun user root
```
Note: `$ openvpn --mktun --dev tun0 --user root` will also work.

```
$ ip link set tun0 up
$ ip addr add 192.168.100.5/24 dev tun0
```

### Establish the simplemux tunnel between machine 4 and machine 5

In machine4:
```
$ ./simplemux -i tun0 -e eth0 -M udp -T tun -c 192.168.0.5
```

In machine5:
```
$ ./simplemux -i tun0 -e eth0 –M udp -T tun -c 192.168.137.4
```
 
### Test the tunnel

Now you can ping from machine 5 or machine 6, to machine 4:
```
$ ping 192.168.100.4
```

The ping arrives to the `tun0` interface of machine 5, goes to machine 4 through the tunnel and is returned to machine 6 through the tunnel.


### Steer traffic from Machine 6 to server x.y.z.t through the tunnel

The idea of simplemux is that it does not run at endpoints, but on some “optimizing” machines in the network. Therefore, you have to define policies to steer the flows of interest, in order to make them go through the TUN interface of the ingress (machine 5). This can be done with `ip rule` and `iptables`.

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

If you show the routes of table 3
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


## Scenario 3: Simplemux between two Virtual Machines in the same computer

Run Simplemux between two VMs with IP addresses `192.168.129.131` and `192.168.129.132`.

They are Debian VMs.


### tun mode

To create a tun, run these commands as root
(To test, you can add an IP address to `tun0`)

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

Run Simplemux in tun tunnel mode (`-T tun` option):

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

Test if Simplemux is working using this command:
```
ping 192.168.100.2
```

If the ping works, it means it sends traffic to the other machine, so Simplemux is working.


### tap mode

Note: RoHC cannot be used in tap tunnel mode (`-r 0` option).

To create a tap, run these commands as root:

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

Test if Simplemux is working using this command:
```
ping 192.168.200.2
```
If the ping works, it means it sends traffic to the other machine, so Simplemux is working.