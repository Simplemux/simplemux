# Simplemux logs

[[_TOC_]]

Using the options `–l [log file name]` or `-L`, you can obtain a text file with traces. This is the format of these traces:

## Trace format

```
                                                                                             +-------------------------+
                                                                                             |    only blast mode      |
+---------+-------+----------------+----+--------+-------+----+----+---------+---------------+--------------+----------+
|timestamp|event  |type            |size|sequence|from/to|IP  |port|number of|triggering     |blast packet  |identifier|
|         |       |                |    |number  |       |    |    |packets  |event(s)       |type          |          |
+---------+-------+----------------+----+--------+-------+----+----+---------+---------------+--------------+----------+
|%"PRIu64"|text   |text            |%i  |%lu     |text   |%s  |%d  |%i       |text           |text          |%"PRIu16" |
+---------+-------+----------------+----+--------+-------+----+----+---------+---------------+--------------+----------+
| usec    |rec    |native          |pckt|number  |-      |-   |-   |-        |-              |-             |-         |
|         |       |                |size|        |       |    |    |         |               |              |          |
|         |       |                |[B] |        |       |    |    |         |               |              |          |
|         |       +----------------+    |        +-------+----+----+         |               +--------------+----------+
|         |       |muxed           |    |        |from   |ingr|port|         |               |blastHeartbeat|identifier|
|         |       |                |    |        |       |IP  |    |         |               |blastPacket   |          |
|         |       |                |    |        |       |    |    |         |               |blastACK      |          |
|         |       +----------------+    |        |       |    |    |         |               +--------------+----------+
|         |       |ROHC_feedback   |    |        |       |    |    |         |               |-             |-         |
|         +-------+----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |sent   |muxed           |    |        |to     |egr |port|number   |numpacket_limit|blastHeartbeat|identifier|
|         |       |                |    |        |       |IP  |    |         |size_limit     |blastPacket   |          |
|         |       |                |    |        |       |    |    |         |timeout        |blastACK      |          |
|         |       |                |    |        |       |    |    |         |period         |              |          |
|         |       |                |    |        |       |    |    |         |MTU            |              |          |
|         |       +----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |       |demuxed         |    |        |-      |-   |-   |-        |-              |-             |-         |
|         +-------+----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |forward|native          |    |        |from   |ingr|port|-        |-              |              |          |
|         |       |                |    |        |       |IP  |    |         |               |              |          |
|         +-------+----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |error  |bad_separator   |    |        |-      |-   |-   |-        |-              |              |          |
|         |       +----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |       |demux_bad_length|    |        |-      |-   |-   |-        |-              |              |          |
|         |       +----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |       |decomp_failed   |    |        |-      |-   |-   |-        |-              |              |          |
|         |       +----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |       |comp_failed     |    |        |-      |-   |-   |-        |-              |              |          |
|         +-------+----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |drop   |too_long        |    |        |to     |egr |port|number   |-              |              |          |
|         |       |                |    |        |       |IP  |    |         |-              |              |          |
|         |       +----------------+    |        +-------+----+----+---------+---------------+--------------+----------+
|         |       |no_ROHC_mode    |    |        |-      |-   |-   |-        |-              |              |          |
+---------+-------+----------------+----+--------+-------+----+----+---------+---------------+--------------+----------+
```

This is the meaning of each parameter:

- `timestamp`: [microseconds]. It is obtained with the function `GetTimeStamp()`.

- `event` and `type`:
    - `rec`: a packet has been received:
        - `native`: a native packet has arrived to the ingress optimizer.
        - `muxed`: a multiplexed packet has arrived to the egress optimizer.
        - `ROHC_feedbac`k: a ROHC feedback-only packet has been received from the decompressor. It only contains ROHC feedback information, so there is nothing to decompress

    - `sent`: a packet has been sent
        - `muxed`: the ingress optimizer has sent a multiplexed packet.
        - `demuxed`: the egress optimizer has demuxed a native packet and sent it to its destination.

    - `forward`: when a packet arrives to the egress with a port different to the one where the optimization is being deployed, it is just forwarded to the network.

    - `error`:
        - `bad_separator`: the Simplemux header before the packet is not well constructed.
        - `demux_bad_length`: the length of the packet expressed in the Simplemux header is excessive (the multiplexed packet would finish after the end of the global packet).
        - `decomp_failed`: ROHC decompression failed.
        - `comp_failed`: ROHC compression failed.

    - `drop`:
        - `no_ROHC_mode`: a ROHC packet has been received, but the decompressor is not in ROHC mode.

- `size`: it expresses (in bytes) the size of the packet. If it is a muxed one, it is the global size of the packet (including the IP header). If it is a native or demuxed one, it is the size of the original (native) packet.

- `sequence number`: it is a sequence number generated internally by the program. Two different sequences are generated: one for received packets and other one for sent packets.

- `IP`: it is the IP address of the peer Simplemux optimizer.
- `port`: it is the destination port of the packet.
- `number of packets`: it is the number of packets included in a multiplexed bundle.
- `triggering event(s)`: it is the cause (more than one may appear) of the triggering of the multiplexed bundle:
    - `numpacket_limit`: the limit of the number of packets has been reached.
    - `size_limit`: the maximum size has been reached.
    - `timeout`: a packet has arrived once the timeout had expired.
    - `period`: the period has expired.
    - `MTU`: the MTU has been reached.


## Trace examples

### Trace examples in normal and fast mode

In the ingress optimizer you may obtain:

```
1417693720928101 rec native 63 1505
1417693720931540 rec native 65 1506
1417693720931643 rec native 52 1507
1417693720936101 rec native 48 1508
1417693720936210 rec native 53 1509
1417693720936286 rec native 67 1510
1417693720937162 rec native 57 1511
1417693720938081 sent muxed 237 1511 to 192.168.137.4 55555 7 period
```

This means that 7 native packets (length `63`, `65`, (...) `57`, and sequence numbers `1505` to `1511`) have been received, and finally the period has expired, so they have been sent together to the egress Simplemux optimizer at `192.168.137.4`, port `55555`.

When the egress optimizer receives this packet, you may obtain this log:

```
1417693720922848 rec muxed 237 210 from 192.168.0.5 55555
1417693720922983 sent demuxed 63 210
1417693720923108 sent demuxed 65 210
1417693720923186 sent demuxed 52 210
1417693720923254 sent demuxed 48 210
1417693720923330 sent demuxed 53 210
1417693720923425 sent demuxed 67 210
1417693720923545 sent demuxed 57 210
```

This means that a multiplexed packet (sequence number `210`) has been received from the ingress optimizer `192.168.0.5` with port `55555`, and it has been demuxed, resulting into 7 different packets of lengths `63`, `65`, (...) `57`.

### Trace examples in blast mode

In *blast* mode, there are more columns in the trace files:

```
1731945249254992	sent	muxed	26	1	to	192.168.1.21		0		blastHeartbeat
1731945250255138	sent	muxed	26	2	to	192.168.1.21		0		blastHeartbeat
1731945251256132	sent	muxed	26	3	to	192.168.1.21		0		blastHeartbeat
1731945252256754	sent	muxed	26	4	to	192.168.1.21		0		blastHeartbeat
1731945253257157	sent	muxed	26	5	to	192.168.1.21		0		blastHeartbeat
1731945254258851	sent	muxed	26	6	to	192.168.1.21		0		blastHeartbeat
1731945255259208	sent	muxed	26	7	to	192.168.1.21		0		blastHeartbeat
1731945255687747	rec	muxed	26	1	from	192.168.1.21		0		blastHeartbeat
1731945256359969	sent	muxed	26	8	to	192.168.1.21		0		blastHeartbeat
1731945256688495	rec	muxed	26	2	from	192.168.1.21		0		blastHeartbeat
1731945257360191	sent	muxed	26	9	to	192.168.1.21		0		blastHeartbeat
1731945257689733	rec	muxed	26	3	from	192.168.1.21		0		blastHeartbeat
1731945258361143	sent	muxed	26	10	to	192.168.1.21		0		blastHeartbeat
1731945258689545	rec	muxed	26	4	from	192.168.1.21		0		blastHeartbeat
1731945259361413	sent	muxed	26	11	to	192.168.1.21		0		blastHeartbeat
1731945259688998	rec	muxed	26	5	from	192.168.1.21		0		blastHeartbeat
1731945260362310	sent	muxed	26	12	to	192.168.1.21		0		blastHeartbeat
1731945260689747	rec	muxed	26	6	from	192.168.1.21		0		blastHeartbeat
1731945261363164	sent	muxed	26	13	to	192.168.1.21		0		blastHeartbeat
1731945261692970	rec	muxed	26	7	from	192.168.1.21		0		blastHeartbeat
1731945262363874	sent	muxed	26	14	to	192.168.1.21		0		blastHeartbeat
1731945262792400	rec	muxed	26	8	from	192.168.1.21		0		blastHeartbeat
1731945263364221	sent	muxed	26	15	to	192.168.1.21		0		blastHeartbeat
1731945263793406	rec	muxed	26	9	from	192.168.1.21		0		blastHeartbeat
1731945264364618	sent	muxed	26	16	to	192.168.1.21		0		blastHeartbeat
1731945264793538	rec	muxed	26	10	from	192.168.1.21		0		blastHeartbeat
1731945265365534	sent	muxed	26	17	to	192.168.1.21		0		blastHeartbeat
1731945265794932	rec	muxed	26	11	from	192.168.1.21		0		blastHeartbeat
1731945266365785	sent	muxed	26	18	to	192.168.1.21		0		blastHeartbeat
1731945266448917	rec	native	84	18
1731945266449025	sent	muxed	110	19	to	192.168.1.21		1		blastPacket	0
1731945266450321	rec	muxed	26	12	from	192.168.1.21		0		blastACK	0
1731945266450439	rec	muxed	110	13	from	192.168.1.21		1		blastPacket	0
1731945266450511	sent	demuxed	84	13
1731945266450563	sent	muxed	26	20	to	192.168.1.21		0		blastACK	0
1731945266794369	rec	muxed	26	14	from	192.168.1.21		0		blastHeartbeat
1731945266950074	rec	native	84	20
1731945266950236	sent	muxed	110	21	to	192.168.1.21		1		blastPacket	1
1731945266951453	rec	muxed	26	15	from	192.168.1.21		0		blastACK	1
1731945266951577	rec	muxed	110	16	from	192.168.1.21		1		blastPacket	1
1731945266951655	sent	demuxed	84	16
1731945266951713	sent	muxed	26	22	to	192.168.1.21		0		blastACK	1
1731945267366152	sent	muxed	26	23	to	192.168.1.21		0		blastHeartbeat
1731945267451583	rec	native	84	23
1731945267451727	sent	muxed	110	24	to	192.168.1.21		1		blastPacket	2
1731945267452948	rec	muxed	26	17	from	192.168.1.21		0		blastACK	2
1731945267453078	rec	muxed	110	18	from	192.168.1.21		1		blastPacket	2
1731945267453157	sent	demuxed	84	18
1731945267453215	sent	muxed	26	25	to	192.168.1.21		0		blastACK	2
1731945267795800	rec	muxed	26	19	from	192.168.1.21		0		blastHeartbeat
1731945267953305	rec	native	84	25
1731945267953475	sent	muxed	110	26	to	192.168.1.21		1		blastPacket	3
1731945267955864	rec	muxed	26	20	from	192.168.1.21		0		blastACK	3
1731945267956048	rec	muxed	110	21	from	192.168.1.21		1		blastPacket	3
1731945267956185	sent	demuxed	84	21
1731945267956258	sent	muxed	26	27	to	192.168.1.21		0		blastACK	3
1731945268366738	sent	muxed	26	28	to	192.168.1.21		0		blastHeartbeat
1731945268454868	rec	native	84	28
1731945268455017	sent	muxed	110	29	to	192.168.1.21		1		blastPacket	4
1731945268456446	rec	muxed	26	22	from	192.168.1.21		0		blastACK	4
1731945268456592	rec	muxed	110	23	from	192.168.1.21		1		blastPacket	4
1731945268456713	sent	demuxed	84	23
1731945268456780	sent	muxed	26	30	to	192.168.1.21		0		blastACK	4
1731945268795801	rec	muxed	26	24	from	192.168.1.21		0		blastHeartbeat
1731945268955919	rec	native	84	30
1731945268956084	sent	muxed	110	31	to	192.168.1.21		1		blastPacket	5
1731945268957057	rec	muxed	26	25	from	192.168.1.21		0		blastACK	5
1731945268957138	rec	muxed	110	26	from	192.168.1.21		1		blastPacket	5
1731945268957215	sent	demuxed	84	26
1731945268957263	sent	muxed	26	32	to	192.168.1.21		0		blastACK	5
1731945269366955	sent	muxed	26	33	to	192.168.1.21		0		blastHeartbeat
1731945269458057	rec	native	84	33
1731945269458190	sent	muxed	110	34	to	192.168.1.21		1		blastPacket	6
1731945269459806	rec	muxed	26	27	from	192.168.1.21		0		blastACK	6
1731945269459929	rec	muxed	110	28	from	192.168.1.21		1		blastPacket	6
1731945269460053	sent	demuxed	84	28
1731945269460105	sent	muxed	26	35	to	192.168.1.21		0		blastACK	6
1731945269795791	rec	muxed	26	29	from	192.168.1.21		0		blastHeartbeat
1731945269959137	rec	native	84	35
1731945269959448	sent	muxed	110	36	to	192.168.1.21		1		blastPacket	7
1731945269963213	rec	muxed	26	30	from	192.168.1.21		0		blastACK	7
1731945269965634	rec	muxed	110	31	from	192.168.1.21		1		blastPacket	7
1731945269966014	sent	demuxed	84	31
1731945269966262	sent	muxed	26	37	to	192.168.1.21		0		blastACK	7
1731945270367692	sent	muxed	26	38	to	192.168.1.21		0		blastHeartbeat
1731945270460697	rec	native	84	38
1731945270460828	sent	muxed	110	39	to	192.168.1.21		1		blastPacket	8
1731945270461630	rec	muxed	26	32	from	192.168.1.21		0		blastACK	8
1731945270461719	rec	muxed	110	33	from	192.168.1.21		1		blastPacket	8
1731945270461793	sent	demuxed	84	33
1731945270461840	sent	muxed	26	40	to	192.168.1.21		0		blastACK	8
1731945270795993	rec	muxed	26	34	from	192.168.1.21		0		blastHeartbeat
1731945271367649	sent	muxed	26	41	to	192.168.1.21		0		blastHeartbeat
1731945271796058	rec	muxed	26	35	from	192.168.1.21		0		blastHeartbeat
1731945272367719	sent	muxed	26	42	to	192.168.1.21		0		blastHeartbeat
```

## Scripts for calculating compression statistics

This repository includes the next Perl scripts:

### Calculate throughput and packets per second with [`simplemux_throughput_pps.pl`](/perl/simplemux_throughput_pps.pl)

Usage:
```
$perl simplemux_throughput_pps.pl <trace file> <tick(us)> <event> <type> <peer IP> <port>
```

It is able to calculate the throughput and the packet-per-second rate, from a Simplemux output trace. The result is in three columns:

```
tick_end_time(us) throughput(bps) packets_per_second
1000000 488144 763
2000000 490504 7 59
3000000 475576 749
4000000 483672 760
5000000 481784 758
6000000 487112 762
7000000 486824 760
8000000 488792 765
9000000 483528 761
10000000 486360 760
```

Usage examples:

```
$ perl simplemux_throughput_pps.pl tracefile.txt 1000000 rec native all all
$ perl simplemux_throughput_pps.pl log_simplemux 1000000 rec muxed all all
$ perl simplemux_throughput_pps.pl log_simplemux 1000000 rec muxed 192.168.0.5 55555
$ perl simplemux_throughput_pps.pl log_simplemux 1000000 sent demuxed
```

### Calculate the multiplexing delay of each packet with [`simplemux_multiplexing_delay.pl`](/perl/simplemux_multiplexing_delay.pl)

Usage:
```
$ perl simplemux_multiplexing_delay.pl <trace file> <output file>
```

The script is able to calculate the multiplexing delay of each packet, from a Simplemux output trace. The multiplexing delay is the time each packet is stopped in the multiplexer, i.e. the interval between its arrival as native packet and its departure inside a multiplexed packet.

The result is an output file in two columns:

```
packet_id multiplexing_delay(us)
1 5279
2 1693
3 1202
4 507
5 10036
6 8471
7 6974
8 5588
9 1143
10 10435
11 8935
12 7522
13 5981
14 4520
15 3011
...
```

And other results are shown in `stdout`:
```
total native packets: 6661
Average multiplexing delay: 5222.47680528449 us
stdev of the multiplexing delay: 3425.575192789 us
```


### Draw the instantaneous throughput and pps with [`simplemux_throughput_pps_live.pl`](/perl/simplemux_throughput_pps_live.pl)

You can make Simplemux generate real-time graphs of the throughput and the amount of packets per second. For that aim, you have to use pipes in order to combine two perl scripts.

You will need to install the `gnuplot-x11` Linux package.

Steps:

1- Send the log of simplemux to `stdout`, using the `–l stdout` option.

2- Use the script [`simplemux_throughput_pps_live.pl`](/perl/simplemux_throughput_pps_live.pl) to generate a summary every e.g. 10 ms of packets coming from (or going to) `192.168.0.5` using port `55555`. The output is something like this:
```
0:492800
1:532000
2:700
3:700
0:492800
1:532000
2:700
3:700
```
Where each row represents a value of

- `0`: native throughput
- `1`: multiplexed throughput
- `2`: native pps
- `3`: multiplexed pps

3- Use the script [`driveGnuPlotStreams.pl`](/perl/driveGnuPlotStreams.pl), by Andreas Bernauer to represent different graphs.

#### Examples

The next command presents two windows, each one with two graphs of 300 samples width, titled “native”, “muxed”, “ppsnat” and “ppsmux”:

```
$ ./simplemux -i tun0 -e eth0 -c 192.168.0.5 -M udp -T tun -d 0 -r 2 -l stdout | perl simplemux_throughput_pps_live.pl 10000 192.168.0.5 55555 | perl ./driveGnuPlotStreams.pl 4 2 300 300 0 1000000 0 200 500x300+0+0 500x300+0+0 'native' 'muxed' 'ppsnat' 'ppsmux' 0 0 1 1
```

The next command presents one window with two graphs of 300 samples width, titled “native” and “muxed”:

```
./simplemux -i tun0 -e eth0 -c 192.168.0.5 -M udp -T tun -d 0 -r 2 -l stdout | perl simplemux_throughput_pps_live.pl 10000 192.168.0.5 | perl ./driveGnuPlotStreams.pl 2 1 300 0 1000000 500x300+0+0 'native' 'muxed' 0 0
```