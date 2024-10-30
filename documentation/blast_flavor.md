# Simplemux *blast flavor*

[[_TOC_]]


In *blast flavor*, all the separators have the same structure:

- **Length** (LEN, 16 bits). This is the length of the multiplexed packet (in bytes).

- **Protocol** (8 bits). It is the Protocol field of the multiplexed packet, according to [IANA "Assigned Internet Protocol Numbers"](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).

- **Identifier** (16 bits). It is unique for each flow (packets in different directions MAY have the same identifier).

- **ACK** (8 bits). It may have three values:
    - `0x00`: this is a normal packet. It requires an ACK
    - `0x01`: the packet is an ACK
    - `0x02`: the packet is a heartbeat

This is the structure of the Simplemux separator in *blast flavor* (fixed size of 6 bytes):
```
                   +-----------------+--------+----------------+--------+
                   |      Length     |Protocol|   Identifier   |   ACK  |
                   +-----------------+--------+----------------+--------+
                          16 bits      8 bits       16 bits      8 bits

normal packet      length muxed packet  prot    sequence number   0x00
                                        muxed
                                        packet

ACK packet                 0x0000        0x00   sequence number   0x01
                                                of acknowledged
                                                packet

heartbeat packet           0x0000        0x00         0x0000      0x02
```

Each packet sent by the multiplexer is stored, and sent periodically until it is acknowledged by the demultiplexer. This increases the traffic, but it guarantees that all the packets arrive to the other side.

Once the acknowledgement of a packet is received, the packet is deleted.

The objective is to ensure that every packet arrives to its destination. A period MUST be defined by the user, so the very same packet is sent periodically until an ACK arrives. 

As a result:
- If a packet is lost, a new copy will be available after an interval similar to the defined period. The delay is not comparable to the RTT. In high-RTT networks this can be quite convenient for certain kinds of packets.
- If the RTT is higher than the defined period, every packet will be sent RTT/period times, i.e. the required bandwidth may be significantly increased.

## Parameters and options

- The user MUST specify a *repeat period*. Note that this is not the *multiplexing period*: in *blast flavor*, the packet is sent immediately, and there is no packet multiplexing. The `-p` option is used to specify the period.
- TCP cannot be used in *blast flavor*: as there is already a mechanism for delivery guarantee, the use of TCP does not make sense.
- RoHC cannot be used: in *blasto flavor*, having a low latency is the priority.


## Examples

### Example 1: Low-RTT network

The next example would happen in a network with a low RTT (Round Trip Time). In this case, the RTT is lower than the blast period, so each packet is sent only once:
```
source        multiplexer     network       demultiplexer      destination
|                  |                                |                   |
|---packet1------->|---ID1-packet1->                |                   |
|                  |                 --ID1-packet1->|                   |
|                  |                 <---ID1-ACK----|-----packet1------>|
|                  |<--ID1-ACK----                  |                   |
|                  |                                |                   |
|---packet2------->|---ID2-packet2->                |                   |
|                  |                 --ID2-packet2->|                   |
|                  |                 <--ID2-ACK-----|-----packet2------>|
|                  |<--ID2-ACK----                  |                   |
```
Note that each packet is acknowledged from the demultiplexer to the multiplexer. The process is transparent for the end machines. In this case, each packet is sent only once between the multiplexer and the demultiplexer.

### Example 2: High-RTT network

In this case, the blast period is smaller than the RTT, so packets are sent a number of times between the multiplexer and the demultiplexer:
```
source        multiplexer     network        demultiplexer      destination
|                  |                                |                   |
|---packet1------->|---ID1-packet1->                |                   |
|                  |                                |                   |
|            period expired                         |                   |
|                  |---ID1-packet1->                |                   |
|                  |                          first copy                |
|                  |                 --ID1-packet1->|                   |
|            period expired          <---ID1-ACK----|-----packet1------>|
|                  |---ID1-packet1->                |                   |
|                  |                          second copy               |
|                  |                 --ID1-packet1->|                   |
|            period expired          <---ID1-ACK----|already delivered  |
|                  |---ID1-packet1->                |                   |
|                  |                          third copy                |
|                  |<--ID1-ACK----   --ID1-packet1->|                   |
|             packet1 deleted        <---ID1-ACK----|already delivered  |
|                  |                                |                   |
|                  |                          fourth copy               |
|                  |<--ID1-ACK----   --ID1-packet1->|                   |
|                  |                 <---ID1-ACK----|already delivered  |
```

In the example, packet1 is sent 4 times between the multiplexer and the demultiplexer. The multiplexer periodically sends a copy of the packet, until it receives the first acknowledgement from the demultiplexer. In that moment, it deletes the stored packet. The subsequent ACK messages are ignored.

When the demultiplexer receives a packet for the first time, it delivers it to the destination, and sends an ACK.

When the demultiplexer receives subsequent copies of the same packet (with the same ID) it does not deliver them to the destination, but it sends a new ACK to the multiplexer.

### Example 3: lossy network with low RTT

This is a lossy network wih low RTT. The first copy of the packet is lost. When the period expires, a copy of the packet is sent. In this case, it arrives.
```
source        multiplexer     network       demultiplexer      destination
|                  |                                |                   |
|---packet1------->|---ID1-packet1->       first copy never arrives     |
|                  |                 --ID1-packet1 X|                   |
|                  |                                |                   |
|                  |                                |                   |
|            period expired                         |                   |
|                  |---ID1-packet1->          second copy               |
|                  |                 --ID1-packet1->|                   |
|                  |                 <---ID1-ACK----|-----packet1------>|
|                  |<--ID1-ACK----                  |                   |
|                  |                                |                   |
|---packet2------->|---ID2-packet2->                |                   |
|                  |                 --ID2-packet2->|                   |
|                  |                 <--ID2-ACK-----|-----packet2------>|
|                  |<--ID2-ACK----                  |                   |
```

In the case of a lost ACK, the packet would be correctly delivered, but the period would expire and a new copy would be sent:
```
source        multiplexer     network       demultiplexer      destination
|                  |                                |                   |
|---packet1------->|---ID1-packet1->            first copy              |
|                  |                 --ID1-packet1->|                   |
|               lost ACK             <---ID1-ACK----|-----packet1------>|
|                  |X -ID1-ACK----                  |                   |
|            period expired                         |                   |
|                  |---ID1-packet1->          second copy               |
|                  |                 --ID1-packet1->|                   |
|                  |                 <---ID1-ACK----|already delivered  |
|                  |<--ID1-ACK----                  |                   |
|                  |                                |                   |
|---packet2------->|---ID2-packet2->                |                   |
|                  |                 --ID2-packet2->|                   |
|                  |                 <--ID2-ACK-----|-----packet2------>|
|                  |<--ID2-ACK----                  |                   |
```

### Example 4: lossy network with high RTT

In this example, the first packet is lost. However, a copy of this packet is delivered, and only an additional delay equal to the defined period is incurred.

The packet arrives two more times, but it is not delivered again.
```
source        multiplexer     network        demultiplexer      destination
|                  |                                |                   |
|---packet1------->|---ID1-packet1->                |                   |
|                  |                                |                   |
|            period expired                         |                   |
|                  |---ID1-packet1->                |                   |
|                  |                      first copy never arrives      |
|                  |                 --ID1-packet1 X|                   |
|            period expired                         |                   |
|                  |---ID1-packet1->                |                   |
|                  |                          second copy               |
|                  |                 --ID1-packet1->|                   |
|            period expired          <---ID1-ACK----|-----packet1------>|
|                  |---ID1-packet1->                |                   |
|                  |                          third copy                |
|                  |<--ID1-ACK----   --ID1-packet1->|                   |
|             packet1 deleted        <---ID1-ACK----|already delivered  |
|                  |                                |                   |
|                  |                          fourth copy               |
|                  |<--ID1-ACK----   --ID1-packet1->|                   |
|                  |                 <---ID1-ACK----|already delivered  |
```