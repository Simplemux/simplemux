Normal flavor
-------------

In _Normal_ flavor, the Simplemux separator has two different formats: one for the First header (the separator before the first packet included in the multiplexed bundle), and another one for Non-first headers (the rest of the separators).

Fig. 7. First and Non-first Simplemux headers (also known as separators)
Format of the First Simplemux header/separator
In order to allow the multiplexing of packets of any length, the number of bytes expressing the length is
variable, and the field Length Extension (LXT, one bit) is set to 0 if the current byte is the last one including
length information.
These are the fields of the header:
- Single Protocol Bit (SPB, one bit) only appears in the first Simplemux header. It is set to 1 if all the
multiplexed packets belong to the same protocol (in this case, the Protocol field will only appear in the first
Simplemux header). It is set to 0 when each packet MAY belong to a different protocol.
- Length Extension (LXT, one bit) is 0 if the current byte is the last byte where the length of the first packet
is included, and 1 in other case.
- Length (LEN, 6, 13, 20, etc. bits). This is the length of the multiplexed packet (in bytes), not including the
length field. If the length of the multiplexed packet is less than 64 bytes (less than or equal to 63 bytes), the
first LXT is set to 0 and the 6 bits of the length field are the length of the multiplexed packet. If the length of
the multiplexed packet is equal or greater than 64 bytes, additional bytes are added. The first bit of each of
the added bytes is the LXT. If LXT is set to 1, it means that there is an additional byte for expressing the
length. This allows to multiplex packets of any length (see Fig. 8).
- Protocol (8 bits) is the Protocol field of the multiplexed packet, according to IANA "Assigned Internet
Protocol Numbers".