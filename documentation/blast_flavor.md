In blast flavor, all the separators have the same structure:

- **Length** (LEN, 16 bits). This is the length of the multiplexed packet (in bytes).

- **Protocol** (8 bits). It is the Protocol field of the multiplexed packet, according to IANA "Assigned Internet Protocol Numbers".

- **Identifier** (16 bits). It is unique for each flow (packets in different directions MAY have the same identifier).

- **ACK** (8 bits). It may have three values:
    - `0`: this is a packet that requires an ACK
    - `1`: the packet is an ACK
    - `2`: the packet is a heartbeat

This is the structure of the Simplemux separator in Blast flavor (fixed size of 6 bytes):
```
+-----------------+--------+----------------+--------+
|      Length     |Protocol|   Identifier   |   ACK  |
+-----------------+--------+----------------+--------+
       16 bits      8 bits       16 bits      8 bits
```

The structure of an ACK is the same, but `length` and `Protocol` MUST always be `0`.

Each packet sent by the multiplexer is stored, and sent periodically until it is acknowledged by the demultiplexer. This increases the traffic, but it guarantees that all the packets arrive to the other side.

Once the acknowledgement of a packet is received, the packet is deleted.

The objective is to ensure that every packet arrives to its destination. A period is defined by the user, so the very same packet is sent periodically until an ACK arrives.

As a result:
- If a packet is lost, a new copy will be available after an interval similar to the defined period. The delay is not comparable to the RTT. In high-RTT networks this can be quite convenient for certain kinds of packets.
- If the RTT is higher than the defined period, every packet will be sent RTT/period times, i.e. the required bandwidth may be significantly increased.

# Examples

## Example 1: Low-RTT network

The next example would happen in a network with a low RTT (Round Trip Time). In this case, the RTT is lower than the blast period, so each packet is sent only once:
```
source        multiplexer     network       demultiplexer      destination
|                  |                               |                   |
|---packet1------->|---ID1-packet1->               |                   |
|                  |                --ID1-packet1->|                   |
|                  |                <---ID1-ACK----|-----packet1------>|
|                  |<--ID1-ACK----                 |                   |
|                  |                               |                   |
|---packet2------->|---ID2-packet2->               |                   |
|                  |                --ID2-packet2->|                   |
|                  |                <--ID2-ACK-----|-----packet2------>|
|                  |<--ID2-ACK----                 |                   |
```
Note that each packet is acknowledged from the demultiplexer to the multiplexer. The process is transparent for the end machines. In this case, each packet is sent only once between the multiplexer and the demultiplexer.

## Example 2: High-RTT network

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
|            period expired          <---ID1-ACK----|already sent       |
|                  |---ID1-packet1->                |                   |
|                  |                          third copy                |
|                  |<--ID1-ACK----   --ID1-packet1->|                   |
|             packet1 deleted        <---ID1-ACK----|already sent       |
|                  |                                |                   |
|                  |                          fourth copy               |
|                  |<--ID1-ACK----   --ID1-packet1->|                   |
|                  |                 <---ID1-ACK----|already sent       |
```

In the example, packet1 is sent 4 times between the multiplexer and the demultiplexer. The multiplexer periodically sends a copy of the packet, until it receives the first acknowledgement from the demultiplexer. In that moment, it deletes the stored packet. The subsequent ACK messages are ignored.

When the demultiplexer receives a packet for the first time, it delivers it to the destination, and sends an ACK.

When the demultiplexer receives subsequent copies of the same packet (with the same ID) it does not deliver them to the destination, but it sends a new ACK to the multiplexer.

## Example 3: lossy network

