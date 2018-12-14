#include "raii_pointer.h"
#include "public_key.h"
#include "packet.h"
#include <iterator>
#include <iostream>
#include <fstream>
#include <cstddef>
#include <vector>
#include <cstdio>

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary gpg packet file>" << std::endl;
        return 1;
    }

    auto file = pgp::make_raii_pointer<std::fclose>(std::fopen(argv[1], "r"));
    std::vector<uint8_t> data;

    if (!file) {
        std::cerr << "Failed to open '" << argv[1] << "' for reading" << std::endl;
        return 1;
    }

    while (!std::feof(file)) {
        uint8_t buffer[4096];

        auto count = std::fread(buffer, 1, sizeof buffer, file);

        data.reserve(data.size() + count);
        std::copy(buffer, buffer + count, std::back_inserter(data));
    }

    pgp::decoder    decoder { data      };
    pgp::packet     packet  { decoder   };

    std::cout << "Packet is of type " << (uint16_t)packet.type() << std::endl;

    auto size = packet.size();

    switch (packet.type()) {
        case pgp::packet_tag::public_key: {
            pgp::public_key key { decoder };
            std::cout << "Have public key packet version " << (int)key.version() << ", created at " << key.creation_time() << " using algorithm " << (int)key.algorithm() << std::endl;
            std::cout << "The public key has " << key.components().size() << " components" << std::endl;
            break;
        }
        default:
            std::cout << "Unhandled packet type: " << (uint16_t)packet.type() << std::endl;
            break;
    }

    if (size) {
        std::cout << "Packet has a body size of " << *size << " bytes" << std::endl;
    } else {
        std::cout << "No size known" << std::endl;
    }

    if (decoder.empty()) {
        std::cout << "All data was read" << std::endl;
    } else {
        std::cout << decoder.size() << " bytes are still available in the decoder" << std::endl;
    }
}
