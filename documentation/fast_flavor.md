# Simplemux fast flavor

In _Fast_ flavor, all the separators have the same structure:

- _Length_ (`LEN`, 16 bits). This is the length of the multiplexed packet (in bytes).

- _Protocol_ (8 bits) field of the multiplexed packet, according to [IANA "Assigned Internet Protocol Numbers"](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).

This is the structure of the Simplemux separator in _Fast_ flavor (fixed size of 3 bytes):
```
+-----------------+--------+
|      Length     |Protocol|
+-----------------+--------+
      16 bits       8 bits
```

This is a Wireshark screenshot showing three multiplexed Ethernet frames (_tap_ tunnel mode), over Simplemux over TCP protocol (_tcp_ mode):

<img src="images/wireshark_3_fast_eth_frames.png" alt="Wireshark screenshot showing three multiplexed Ethernet frames over Simplemux over TCP protocol" width="600"/>