# PGP packet decoder and encoder

## Table of Contents

- [Introduction](#introduction)
- [Building the library](#building-the-library)
- [Using the library](#using-the-library)


## Introduction

This library implements part of [RFC 4880](https://tools.ietf.org/html/rfc4880) and [RFC 6637](https://tools.ietf.org/html/rfc6637), allowing the decoding and encoding of binary PGP packets.

The library is centered around the pgp::packet class. This class can be constructed with packet-specific data to be encoded, or it can be constructed from encoded data - to easily access the fields. Reading or writing packets requires a pgp::decoder or a pgp::encoder, specifically. Since these deal with binary data, they require a range of bytes (in our case, it's uint8_t). The decoder will consume bytes from this range, while the encoder will write bytes to it.

## Building the library

To build the library, the following dependencies need to be installed first:
- libboost
- libsodium
- crypto++

Since this library uses submodules, it will not build unless they are also checked out. To check out all the submodules used in the project, execute the following command:

`git submodule update --init`

The recommended way to then build the library is to do a so-called out-of-source build. This ensures that any build-related files do not clutter the repository itself and makes it easy to get rid of any build-artifacts. Assuming you'd want to build in a directory called `build`, the following set of commands should be enough:

```bash
mkdir -p build && cd build && cmake .. && cd -
make -C build
```

If you wish to install the library - so that it can be automatically found by projects using it, you could then execute the following command:

`make -C build install`

This command might need administrative privileges. Depending on your operating system and configuration, you might need to use `sudo` or change to an administrative user before executing the command.

## Using the library

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

Of course, creating packets by directly constructing them with data
is interesting, but this wouldn't be much use if we could not share
the data between compatible PGP implementations.

In order to provide this interoperability, the packet class is also
constructible from a decoder class - translating binary packet data
to be parsed - and also provides an encode function, exporting data
to an encoder, producing binary output.

Let's look at an example, once again using the user_id type (due to
its simplicity), writing it out to binary and then reading this raw
data again to verify that we got the exact same packet again.

```c++
#include <pgp-packet/packet.h>
#include <iostream>
#include <cassert>
#include <vector>

int main()
{
    // create our simple user id packet
    pgp::packet packet{
        mpark::in_place_type_t<pgp::user_id>{},
        std::string{ "Anne Onymous <anonymous@example.org>" }
    };

    // create a buffer for storing the binary data - we allocate the
    // exact number of bytes the packet requests, and then we create
    // a range_encoder around it. the range_encoder works by writing
    // the raw data to a provided range of bytes, which must stay in
    // scope during the encoder operation.
    std::vector<uint8_t> data(packet.size());
    pgp::range_encoder   encoder{ data };

    // write out the packet data to the given buffer
    packet.encode(encoder);

    // now create a decoder to decode the freshly filled data buffer
    // and use this decoder to create a second packet containing the
    // same user id body with the exact same data
    pgp::decoder decoder{ data };
    pgp::packet  copied_packet{ decoder };

    // the packets should be identical
    assert(packet == copied_packet);

    return 0;
}
```
