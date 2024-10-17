# Simplemux logs

Using the options `–l [log file name]` or `-L`, you can obtain a text file with traces. This is the format of these traces:

```
+---------+-----+-------------+----+--------+-------+----+----+---------+---------------+
|timestamp|event|type         |size|sequence|from/to|IP  |port|number of|triggering     |
|         |     |             |    |number  |       |    |    |packets  |event(s)       |
+---------+-----+-------------+----+--------+-------+----+----+---------+---------------+
|%"PRIu64"|text |text         |%i  |%lu     |text   |%s  |%d  |%i       |text           |
+---------+-----+-------------+----+--------+-------+----+----+---------+---------------+
| usec    |rec  |native       |pckt|number  |-      |-   |-   |-        |-              |
|         |     |             |size|        |       |    |    |         |               |
|         |     |             |[B] |        |       |    |    |         |               |
|         |     +-------------+    |        +-------+----+----+         |               |
|         |     |muxed        |    |        |from   |ingr|port|         |               |
|         |     |             |    |        |       |IP  |    |         |               |
|         |     +-------------+    |        |       |    |    |         |               |
|         |     |ROHC_feedback|    |        |       |    |    |         |               |
|         +-----+-------------+    |        +-------+----+----+---------+---------------+
|         |sent |muxed        |    |        |to     |egr |port|number   |numpacket_limit|
|         |     |             |    |        |       |IP  |    |         |size_limit     |
|         |     |             |    |        |       |    |    |         |timeout        |
|         |     |             |    |        |       |    |    |         |period         |
|         |     |             |    |        |       |    |    |         |MTU            |
|         |     +-------------+    |        +-------+----+----+---------+---------------+
|         |     |demuxed      |    |        |-      |-   |-   |-        |-              |     
|         |     +-------------+    |        +-------+----+----+---------+---------------+

from
ingress IP address
port
(only in transport mode)
ROHC_feedback
sent
muxed
to
egress IP address
port
(only in transport mode)
number
numpacket_limit
size_limit
timeout
period
MTU
demuxed
-
-
-
-
-
forward
native
from
ingress IP address
port
-
-
error
bad_separator
-
-
-
-
-
demux_bad_length
-
-
-
-
-
decomp_failed
-
-
-
-
-
comp_failed
-
-
-
-
-
drop
too_long
to
egress IP address
port
number
-

drop
no_ROHC_mode
-
-
-
-
-
- timestamp: it is in microseconds. It is obtained with the function GetTimeStamp().
- event and type:
- rec: a packet has been received:
- native: a native packet has arrived to the ingress optimizer.
- muxed: a multiplexed packet has arrived to the egress optimizer.
- ROHC_feedback: a ROHC feedback-only packet has been received from the decompressor. It only contains ROHC feedback information, so there is nothing to decompress
- sent: a packet has been sent
- muxed: the ingress optimizer has sent a multiplexed packet.
- demuxed: the egress optimizer has demuxed a native packet and sent it to its destination.
- forward: when a packet arrives to the egress with a port different to the one where the optimization is being deployed, it is just forwarded to the network.
- error:
- bad_separator: the Simplemux header before the packet is not well constructed.
- demux_bad_length: the length of the packet expressed in the Simplemux header is excessive (the multiplexed packet would finish after the end of the global packet).
- decomp_failed: ROHC decompression failed.
- comp_failed: ROHC compression failed.
- drop:
- no_ROHC_mode: a ROHC packet has been received, but the decompressor is not in ROHC mode.
- size: it expresses (in bytes) the size of the packet. If it is a muxed one, it is the global size of the packet (including IP header). If it is a native or demuxed one, it is the size of the original (native) packet.
- sequence number: it is a sequence number generated internally by the program. Two different sequences are generated: one for received packets and other one for sent packets.
- IP: it is the IP address of the peer Simplemux optimizer.
- port: it is the destination port of the packet.
- number of packets: it is the number of packets included in a multiplexed bundle.
- triggering event(s): it is the cause (more than one may appear) of the triggering of the multiplexed bundle:
- numpacket_limit: the limit of the number of packets has been reached.
- size_limit: the maximum size has been reached.
- timeout: a packet has arrived once the timeout had expired.
- period: the period has expired.
- MTU: the MTU has been reached.