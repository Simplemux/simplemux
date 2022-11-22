Simplemux: use of RoHC
----------------------

This Simplemux implementation includes these ROHC modes:
- ROHC unidirectional.
- ROHC bidirectional optimistic
- ROHC bidirectional reliable is not yet implemented.

ROHC cannot be enabled in one of the peers and disabled in the other peer.

ROHC is able to compress these kinds of traffic flows:
- IP/UDP/RTP: If the UDP packets have the destination ports 1234, 36780, 33238, 5020, 5002, the compressor assumes that they are RTP.
- IP/UDP
- IP/TCP
- IP/ESP
- IP/UDP-Lite