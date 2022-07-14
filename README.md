# PGP packet decoder and encoder

![](https://github.com/summitto/pgp-packet-library/workflows/ubuntu-latest/badge.svg)
![](https://github.com/summitto/pgp-packet-library/workflows/macos-latest/badge.svg)

**Please note: this is not (yet) production-ready code. Proceed with caution.**

- [PGP packet decoder and encoder](#pgp-packet-decoder-and-encoder)
  - [Introduction](#introduction)
  - [Building the library](#building-the-library)
  - [Using the library](#using-the-library)
    - [Creating a simple packet](#creating-a-simple-packet)
    - [Encoding and decoding of packet data](#encoding-and-decoding-of-packet-data)
    - [Creating a PGP key from raw point data](#creating-a-pgp-key-from-raw-point-data)
  - [Verifying the library](#verifying-the-library)
    - [Clang Tidy](#clang-tidy)
    - [Static analysis using Cppcheck](#static-analysis-using-cppcheck)
    - [Credits](#credits)

## Introduction

This library implements part of [RFC 4880](https://tools.ietf.org/html/rfc4880) and [RFC 6637](https://tools.ietf.org/html/rfc6637), allowing the decoding and encoding of binary PGP packets.

The library is centered around the pgp::packet class. This class can be constructed with packet-specific data to be encoded, or it can be constructed from encoded data - to easily access the fields. Reading or writing packets requires a `pgp::decoder` or a `pgp::encoder`, respectively. Since these deal with binary data, they require a range of bytes (in our case, that's `uint8_t`). The decoder will consume bytes from this range, while the encoder will write bytes to it.

## Building the library

The library has been tested to work with the following C++ compilers:
| Compiler    | Version(s)               | Environment    |
|:------------|:------------------------:|:---------------|
| Apple clang | `13.0.0.13000029`        | `macOS-11.6.6` |
| clang++     | `6.0.1`/`9.0.1`/`14.0.0` | `ubuntu-20.04` |
| g++         | `8.4.0`/`9.4.0`/`11.2.0` | `ubuntu-20.04` |

[The compiler crashes](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91058) for versions of g++ lower than 8.0

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
cmake -B build && make -C build
```

If you wish to install the library (so that it can be automatically found by projects using it), you could then execute the following command:

```bash
make -C build install
```

This command might need administrative privileges. Depending on your operating system and configuration, you might need to use `sudo` or change to an administrator account before executing the command.

## Using the library

The easiest way to use the library is by setting up a CMake project and use the provided CMake modules under `cmake/Modules` to locate the dependencies, a clear example of how to do it can be found in the [pgp-key-generation repository](https://github.com/summitto/pgp-key-generation/).

The library provides a CMake configuration file which sets up all the needed dependencies, the following `CMakeLists.txt` should be enough to run the code examples
```cmake
cmake_minimum_required(VERSION 3.13.0)

project(pgp-packet-example
        VERSION 0.1.1
        LANGUAGES CXX)

find_package(pgp-packet-packet REQUIRED)

add_executable(pgp-packet-example example.cpp)
target_link_libraries(pgp-packet-example pgp-packet)
```

Otherwise the dependencies need to be installed and linked manually

### Creating a simple packet

Since PGP packets can contain very different types of data, the body of the `pgp::packet` is an `std::variant`, which gives easy access to the packet-specific fields. If for some reason your standard library is outdated and does not provide `std::variant`, the library falls back to a bundled third-party variant implementation called `mpark::variant`. A type alias for the variant class and it's helper definitions is provided under the `pgp namespace` to make use of the right package.

 When constructing a packet, the packet type must be provided as well. [Let's look at an example](examples/create_simple_packet.cpp) for the simplest type of packet, the user id.

### Encoding and decoding of packet data

Of course, creating packets by directly constructing them with data
is interesting, but this wouldn't be of much use if we couldn't
share the data between compatible PGP implementations.

In order to provide this interoperability, the `packet` class
provides a constructor taking an instance of the `decoder` class,
which parses the binary data read by the decoder, and has an
`encode` method, which produces the binary representation and
passes it to an `encoder` instance.

[Let's look at an example](examples/encoding_and_decoding.cpp),
once again using the user_id type (due to its simplicity).
The packet is encoded to its binary representation, which is then
read. We verify that this indeed results in the same
packet as we started with.

Note the use of `pgp::vector`, this is an alias for an `std::vector`
using a custom allocator which prevents the data from being swapped
to disk, as well as erasing the memory before freeing it.

### Creating a PGP key from raw point data

Sometimes it can be useful to use existing keys - e.g. an elliptic curve point - and import them in PGP. PGP does not have an easy way to do this, unless the keys are already wrapped in the PGP packet headers, come with an associated user id packet, and a signature attesting the ownership of the user for the given key.

In this - somewhat more complex - example, we'll create an ed25519 private and public key pair using libsodium and then use this to create a set of packets that can be imported into a PGP-compatible client.

[This example](examples/key_from_raw_data.cpp) should provide a bit more insight into the structure of PGP keys. We will create three packets. The first is the secret-key packet: it contains the actual key data, the key type, and the time the key was created. The second packet contains the user id; this one is pretty self-explanatory. The third and final packet contains a signature, which attests that the key belongs to the user id mentioned before. Let's dive into the code.

## Verifying the library

### Clang Tidy

If `clang-tidy` is installed, then CMake will create a `tidy` target that can be used to run `clang-tidy` over the codebase. The configuration for the checkers can be found in the `.clang-tidy` file in the root of the repository.

### Static analysis using Cppcheck

If [Cppcheck](http://cppcheck.sourceforge.net/) is found on the system,
the `cppcheck` make target can be used to run static analysis on the
source code. Any warnings will mark the check as failed.

The checks enabled can be found in `CMakeLists.txt` and the existing
exceptions to rules can be found in `CppCheckSuppressions.txt`. Do make
sure that adding new code doesn't fail the existing tests.

### Credits

Martijn Otto

Tom Smeding

Sascha Jafari

Victor Sint Nicolaas

Andrés Nicolini
