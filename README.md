# PGP packet decoder and encoder

**Please note: this is not (yet) production-ready code. Proceed with caution.**

- [Introduction](#introduction)
- [Building the library](#building-the-library)
- [Using the library](#using-the-library)
  - [Creating a simple packet](#creating-a-simple-packet)
  - [Encoding and decoding of packet data](#encoding-and-decoding-of-packet-data)
  - [Creating a PGP key from raw point data](#creating-a-PGP-key-from-raw-point-data)
- [Verifying the library](#verifying-the-library)
  - [Clang Tidy](#clang-tidy)
  - [Static analysis using Cppcheck](#static-analysis-using-cppcheck)

## Introduction

This library implements part of [RFC 4880](https://tools.ietf.org/html/rfc4880) and [RFC 6637](https://tools.ietf.org/html/rfc6637), allowing the decoding and encoding of binary PGP packets.

The library is centered around the pgp::packet class. This class can be constructed with packet-specific data to be encoded, or it can be constructed from encoded data - to easily access the fields. Reading or writing packets requires a `pgp::decoder` or a `pgp::encoder`, respectively. Since these deal with binary data, they require a range of bytes (in our case, that's `uint8_t`). The decoder will consume bytes from this range, while the encoder will write bytes to it.

## Building the library

The library has been tested to work with the following C++ compilers:

- g++ >= 8.0 ([fails with versions &lt; 8.0](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91058))
- clang++ 8.0.0, 7.1.0, 7.0.1, 6.0, Apple clang 10.0.0

To build the library, the following dependencies need to be installed first:
- [Boost C++ libraries](https://www.boost.org/)
- [Libsodium](https://download.libsodium.org/doc/)
- [Crypto++ Library](https://cryptopp.com/)

Since this library uses submodules, it will not build unless they are also checked out. To check out all the submodules used in the project, execute the following command:

```bash
git submodule update --init
```

The recommended way to then build the library is to do a so-called out-of-source build. This ensures that any build-related files do not clutter the repository itself and makes it easy to get rid of any build artifacts. Assuming you want to build in a directory called `build`, the following set of commands should be enough:

```bash
mkdir -p build && cd build && cmake .. && cd ..
make -C build
```

If you wish to install the library (so that it can be automatically found by projects using it), you could then execute the following command:

`make -C build install`

This command might need administrative privileges. Depending on your operating system and configuration, you might need to use `sudo` or change to an administrator account before executing the command.

## Using the library

### Creating a simple packet

Since PGP packets can contain very different types of data, the body of the `pgp::packet` is an `std::variant`, which gives easy access to the packet-specific fields. If for some reason your standard library is outdated and does not provide `std::variant`, the library falls back to a bundled third-party variant implementation called `mpark::variant`. For the sake of the examples, we will assume an up-to-date standard library.

 When constructing a packet, the packet type must be provided as well. Let's look at an example for the simplest type of packet, the user id:

```c++
#include <pgp-packet/packet.h>
#include <iostream>

int main()
{
    // when constructing a packet we must specify the body type that
    // is to be contained within the packet; the constructor for the
    // packet uses the same pattern a regular std::variant uses when
    // forwarding constructors. the first - unnamed - parameter sets
    // the alternative to construct inside the variant, while others
    // get forwarded to the constructor of the selected alternative.
    //
    // since a user_id packet has a constructor using an std::string
    // we can construct a user_id packet like this:
    pgp::packet packet{
        std::in_place_type_t<pgp::user_id>{},
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
    auto &body = std::get<pgp::user_id>(packet.body());

    // now we have access to the user_id body, which provides simple
    // getters for its relevant members. in this case, it's only the
    // id itself that is stored, which can be retrieved using the id
    // member function.
    std::cout
        << "Stored user id: "
        << body.id()
        << std::endl;
}
```

### Encoding and decoding of packet data

Of course, creating packets by directly constructing them with data
is interesting, but this wouldn't be of much use if we couldn't
share the data between compatible PGP implementations.

In order to provide this interoperability, the `packet` class
provides a constructor taking an instance of the `decoder` class,
which parses the binary data read by the decoder, and has an
`encode` method, which produces the binary representation and
passes it to an `encoder` instance.

Let's look at an example, once again using the user_id type (due to
its simplicity). The packet is encoded to its binary representation,
which is then read. We verify that this indeed results in the same
packet as we started with.

```c++
#include <pgp-packet/packet.h>
#include <iostream>
#include <cassert>
#include <vector>

int main()
{
    // create our simple user id packet
    pgp::packet packet{
        std::in_place_type_t<pgp::user_id>{},
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
}
```

### Creating a PGP key from raw point data

Sometimes it can be useful to use existing keys - e.g. an elliptic curve point - and import them in PGP. PGP does not have an easy way to do this, unless the keys are already wrapped in the PGP packet headers, come with an associated user id packet, and a signature attesting the ownership of the user for the given key.

In this - somewhat more complex - example, we'll create an ed25519 private and public key pair using libsodium and then use this to create a set of packets that can be imported into a PGP-compatible client.

This example should provide a bit more insight into the structure of PGP keys. We will create three packets. The first is the secret-key packet: it contains the actual key data, the key type, and the time the key was created. The second packet contains the user id; this one is pretty self-explanatory. The third and final packet contains a signature, which attests that the key belongs to the user id mentioned before. Let's dive into the code:


```c++
#include <pgp-packet/packet.h>
#include <iostream>
#include <sodium.h>
#include <vector>

int main()
{
    // create vectors holding the secret and public key points, note
    // that we take an extra byte for the public key, since pgp will
    // need an extra byte in front of it, it is always the same byte
    // for this key type, so it doesn't add any real information but
    // pgp still requires it and throws a fit if it is missing.
    std::vector<uint8_t> public_key_data(crypto_sign_PUBLICKEYBYTES + 1);
    std::vector<uint8_t> secret_key_data(crypto_sign_SECRETKEYBYTES);

    // now create a new keypair to be imported into pgp, as noted in
    // the declaration above, we have to ignore the first byte as we
    // need to set a special tag byte here for pgp to recognize it
    // note: error checks are skipped here for brevity
    crypto_box_keypair(public_key_data.data() + 1, secret_key_data.data());

    // libsodium puts both the secret key and the public key data in
    // the secret key buffer, which pgp does not need, therefore the
    // extra data must be truncated before creating the key
    secret_key_data.resize(32);

    // now set the tag byte required for pgp
    public_key_data[0] = 0x04;

    // define the creation time of this key (as a unix timestamp)
    // and the expiration time (another unix timestamp), we define
    // the key as being valid for 3600 seconds (an hour);
    uint32_t creation = 1559737787;
    uint32_t expiration = creation + 3600;

    // now create a packet containing this secret key
    pgp::packet secret_key_packet{
        std::in_place_type_t<pgp::secret_key>{},                        // we are building a secret key
        creation,                                                       // created at this unix timestamp
        pgp::key_algorithm::eddsa,                                      // using the eddsa key algorithm
        std::in_place_type_t<pgp::secret_key::eddsa_key_t>{},           // create a key of the eddsa type
        std::forward_as_tuple(                                          // arguments for the public key
            pgp::curve_oid::ed25519(),                                  // which curve to use
            pgp::multiprecision_integer{ std::move(public_key_data) }   // move in the public key point
        ),
        std::forward_as_tuple(                                          // secret arguments
            pgp::multiprecision_integer{ std::move(secret_key_data) }   // copy in the secret key point
        )
    };

    // create a packet describing the user owning this key
    pgp::packet user_id_packet{
        std::in_place_type_t<pgp::user_id>{},
        std::string{ "Anne Onymous <anonymous@example.org>" }
    };

    // to complete the set, we need to create a signature packet,
    // which certifies that we are the owners of this key.
    pgp::packet signature_packet{
        std::in_place_type_t<pgp::signature>{},                         // we are making a signature
        std::get<pgp::secret_key>(secret_key_packet.body()),            // we sign it with the secret key
        std::get<pgp::user_id>(user_id_packet.body()),                  // for the given user
        pgp::signature_subpacket_set{{                                  // hashed subpackets
            pgp::signature_creation_time_subpacket  { creation      },  // signature creation time
            pgp::key_expiration_time_subpacket      { expiration    },  // signature expiration time
            pgp::key_flags_subpacket                { 0x01, 0x02    },  // the privileges for the main key (signing and certification)
        }},
        pgp::signature_subpacket_set{{                                  // unhashed subpackets
            pgp::issuer_subpacket {                                     // fingerprint of the key we are signing with
                std::get<pgp::secret_key>(secret_key_packet.body()).fingerprint()
            }
        }}
    };

    // we now have a set of packets, which, when encoded to a file, can
    // be imported into a compatible pgp implementation (such as gnupg)
    std::vector<uint8_t> data(
        secret_key_packet   .size() +
        user_id_packet      .size() +
        signature_packet    .size()
    );

    // create an encoder writing in the vectors range
    pgp::range_encoder encoder{ data };

    // encode all the packets into the encoder
    secret_key_packet   .encode(encoder);
    user_id_packet      .encode(encoder);
    signature_packet    .encode(encoder);

    // the encoder has now filled the vector with data, which can be written
    std::ofstream   output{ "keyfile" };
    output.write(reinterpret_cast<const char*>(data.data()), data.size());

    return 0;
}
```

# Verifying the library

## Clang Tidy

If `clang-tidy` is installed, then CMake will create a `tidy` target that can be used to run `clang-tidy` over the codebase. The configuration for the checkers can be found in the `.clang-tidy` file in the root of the repository.

## Static analysis using Cppcheck

If [Cppcheck](http://cppcheck.sourceforge.net/) is found on the system,
the `cppcheck` make target can be used to run static analysis on the
source code. Any warnings will mark the check as failed.

The checks enabled can be found in `CMakeLists.txt` and the existing
exceptions to rules can be found in `CppCheckSuppressions.txt`. Do make
sure that adding new code doesn't fail the existing tests.

# Credits

Martijn Otto

Tom Smeding

Sascha Jafari

Victor Sint Nicolaas
