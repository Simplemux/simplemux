In blast flavor, all the separators have the same structure:

- **Length** (LEN, 16 bits). This is the length of the multiplexed packet (in bytes).

- **Protocol** (8 bits). It is the Protocol field of the multiplexed packet, according to IANA "Assigned Internet Protocol Numbers".

- **Identifier** (16 bits). It is unique for each flow (packets in different directions MAY have the same identifier).

- **ACK** (8 bits). It may have three values:
    - 0:this is a packet that requires an ACK
    - 1:the packet is an ACK
    - 2: the packet is a heartbeat

This is the structure of the Simplemux separator in Blast mode:
```
+-----------------+--------+----------------+--------+
|      Length     |Protocol|   Identifier   |   ACK  |
+-----------------+--------+----------------+--------+
       16 bits      8 bits       16 bits      8 bits
```

The structure of an ACK is the same one, but `length` and `Protocol` are always `0`.

Each packet sent by the multiplexer is stored, and sent periodically until it is acknowledged by the demultiplexer. This increases the traffic, but it guarantees that all the packets arrive to the other side.

Once the acknowledgement of a packet is received, the packet is deleted.