PGP packet decoder and encoder
==============================

This library implements part of [RFC 4880](https://tools.ietf.org/html/rfc4880) and [RFC 6637](https://tools.ietf.org/html/rfc6637), allowing the decoding and encoding of binary PGP packets.

The library is centered around the pgp::packet class. This class can be constructed with packet-specific data to be encoded, or it can be constructed from encoded data - to easily access the fields. Reading or writing packets requires a pgp::decoder or a pgp::encoder, specifically. Since these deal with binary data, they require a range of bytes (in our case, it's uint8_t). The decoder will consume bytes from this range, while the encoder will write bytes to it.

DEPENDENCIES
============

This project depends on
- libboost
- libsodium
- crypto++

USING THE LIBRARY
=================

Since PGP packets can contain very different types of data, the body of the pgp::packet is an std::variant, which gives easy access to the packet-specific fields. When constructing a packet, the packet type must be provided as well. Let's look at an example for the simplest type of packet, the user id:

```c++
#include <pgp-packet/packet.h>
#include <iostream>

int main()
{
    // when constructing a packet we must specify the body type that
    // is to be contained within the packet, the constructor for the
    // packet uses the same pattern a regular std::variant uses when
    // forwarding constructors. the first - unnamed - parameter sets
    // the alternative to construct inside the variant, while others
    // get forwarded to the constructor of the selected alternative.
    //
    // since a user_id packet has a constructor using an std::string
    // we can construct a user_id packet like this:
    pgp::packet packet{
        mpark::in_place_type_t<pgp::user_id>{},
        std::string{ "Anne Onymous <anonymous@example.org>" }
    };

    // packets have a tag function, which returns an enum indicating
    // the type of packet contained inside the body. there is a free
    // function called packet_tag_description which can be used when
    // debugging or otherwise creating a description of a packet.
    std::cout
        << "Packet type: "
        << pgp::packet_tag_description(packet.tag())
        << std::endl;

    // besides getting the packet type, using the tag() function, it
    // is also possible to get to the body of the packet through the
    // body() function of the packet. since this is simply a variant
    // as provided by the STL, it can either be visit()'ed (whenever
    // writing generic code), or an explicit std::get can be done to
    // retrieve a specific type of body - which could throw an error
    // if the body is of a different type than the one requested. in
    // this case we are certain that the body will contain a user_id
    auto &body = mpark::get<pgp::user_id>(packet.body());

    // now we have access to the user_id body, which provides simple
    // getters for its relevant members. in this case, it's only the
    // id itself that is stored, which can be retrieved using the id
    // member function.
    std::cout
        << "Stored user id: "
        << body.id()
        << std::endl;

    return 0;
}
```
