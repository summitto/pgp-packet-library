PGP packet decoder and encoder

This library implements part of [RFC 4480](https://tools.ietf.org/html/rfc4880) and [RFC 6637](https://tools.ietf.org/html/rfc6637), allowing the decoding and encoding of binary PGP packets.

The library is centered around the pgp::packet class. This class can be constructed with packet-specific data to be encoded, or it can be constructed from encoded data - to easily access the fields. Reading or writing packets requires a pgp::decoder or a pgp::encoder, specifically. Since these deal with binary data, they require a range of bytes (in our case, it's uint8_t). The decoder will consume bytes from this range, while the encoder will write bytes to it.

When the range is completely used - either because the decoder consumed all the bytes, or the encoder has written to all of them - consuming or writing data will throw an exception. To make sure a packet can fit within a range, it has a `size()` method. Writing a packet to a range of this size is guaranteed to not throw.

DEPENDENCIES
============

This project depends on
- libboost
- libgcrypt
- libsodium
