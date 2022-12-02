Simplemux fast flavor
---------------------

In fast flavor, all the separators have the same structure:

- **Length** (LEN, 16 bits). This is the length of the multiplexed packet (in bytes).

- **Protocol** (8 bits). It is the Protocol field of the multiplexed packet, according to IANA "Assigned Internet Protocol Numbers".

This is the structure of the Simplemux separator in Fast flavor (fixed size of 3 bytes):
```
+-----------------+--------+
|      Length     |Protocol|
+-----------------+--------+
        16 bits     8 bits
```