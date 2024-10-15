Simplemux: multiplexing policies
--------------------------------

**Note**. In *blast* flavor, only a single packet can be sent. In that case, only the *period* can be used.

Four different conditions can be used and combined for triggering the sending of a multiplexed packet:
- Number of packets
- Size
- Timeout
- Period

More than one condition can be set at the same time. Please note that if (timeout > period), then the timeout has no effect. Note that only the *period* policy guarantees an upper bound for the multiplexing delay.

Simplemux is symmetric, i.e. both machines may act as ingress and egress simultaneously. However, different policies can be established at each of the optimizers, e.g. in one side you can send a multiplexed packet every two native ones, and in the other side you can set a timeout.

## *number of packets* (`-n`)

A number of packets have arrived at the multiplexer.

## *size* (`-B`)

Two different options apply:
    - the size of the multiplexed packet has exceeded the size threshold specified by the user, but not the MTU. In this case, a packet is sent, and a new period is started with the buffer empty.
    - the size of the multiplexed packet has exceeded the MTU (and the size threshold consequently). In this case, a packet is sent without the last one. A new period is started, and the last arrived packet is stored for the next period.

If you want to specify an MTU different from the one of the local interface, you can use the `-m` option.

You may use other tools for getting the MTU of a network path. For example with the command:
```
$ tracepath 192.168.137.3 | grep Resume | cut -c 19-22
```
you will obtain the MTU of the path to 192.168.137.3.

## *timeout* (`-t`)

A packet arrives, and a timeout since the last sending has expired.

## *period* (`-P`)

An active waiting is performed, and a multiplexed packet including all the packets arrived during a period is sent.

Note: in *blast* flavor, the parameter *period* (option `-P`) is used in order to specify the period that wil be employed for sending the copies of a packet.

# Examples of the different policies

Set a period of 50 ms
```
$ ./simplemux -i tun0 -e eth0 –M udp -T tun -c 192.168.0.5 –P 50000
```

Send a multiplexed packet every 2 packets, use ROHC Bidirectional Optimistic
```
$ ./simplemux -i tun0 -e eth0 –M udp -T tun -c 192.168.0.5–n 2 –r 2
```

Send a multiplexed packet if the size of the multiplexed bundle is 400 bytes
```
$ ./simplemux -i tun0 -e eth0 –M udp -T tun -c 192.168.0.5 –b 400
```

Send a timeout of 50ms, and a period of 100 ms (to set an upper bound on the added delay), use ROHC Unidirectional
```
$ ./simplemux -i tun0 -e eth0 –M udp -T tun -c 192.168.0.5 –t 50000 –P 100000 –r 1
```

# If you have to use the same local interface more than once

It may happen that you have to create more than one tunnel using the same local interface. In that case, you may obtain a message Is already in use.

For example, if you run these two commands in the same machine, you may obtain this error message:
```
./simplemux -i tun0 -e wlan0 -M network -T tun -c 10.1.10.4
./simplemux -i tun1 -e wlan0 -M network -T tun -c 10.1.10.6
```

To avoid the problem, you can use an alias (see e.g. https://www.cyberciti.biz/faq/linux-creating-or-adding-new-network-alias-to-a-network-card-nic/). So you can do `$ ifconfig wlan0:0 x.y.z.t up`, and then you can use `wlan0` in one case, and `wlan0:0` in the other.