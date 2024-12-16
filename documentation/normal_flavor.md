Normal flavor
-------------

In _Normal_ flavor, the Simplemux separator has two different formats: one for the _First header_ (the separator before the first packet included in the multiplexed bundle), and another one for _Non-first headers_ (the rest of the separators).

<img src="images/first_vs_non-first.png" alt="First and Non-first Simplemux headers (also known as _separators_)" width="600"/>

# Format of the First Simplemux header/separator

In order to allow the multiplexing of packets of any length, the number of bytes expressing the length is variable, and the field _Length Extension_ (`LXT`, one bit) is set to `0` if the current byte is the last one including length information.

These are the fields of the header:
- _Single Protocol Bit_ (`SPB`, one bit) only appears in the first Simplemux header. It is set to `1` if all the multiplexed packets belong to the same protocol (in this case, the `Protocol` field will only appear in the first Simplemux header). It is set to `0` when each packet MAY belong to a different protocol.
- _Length Extension_ (`LXT`, one bit) is `0` if the current byte is the last byte where the length of the first packet is included, and `1` in other case.
- _Length_ (`LEN`, 6, 13, 20, etc. bits). This is the length of the multiplexed packet (in bytes), not including the _Length_ field. If the length of the multiplexed packet is less than 64 bytes (less than or equal to 63 bytes), the first `LXT` is set to `0` and the 6 bits of the length field are the length of the multiplexed packet. If the length of the multiplexed packet is equal or greater than 64 bytes, additional bytes are added. The first bit of each of
the added bytes is the `LXT`. If `LXT` is set to `1`, it means that there is an additional byte for expressing the length. This allows to multiplex packets of any length (see the figure).
- _Protocol_ (8 bits) field of the multiplexed packet, according to [IANA "Assigned Internet
Protocol Numbers"](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).

<img src="images/first_separator_fields.png" alt="Fields of the First Simplemux header/separator" width="600"/>