#include "raii_pointer.h"
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

    pgp::decoder                decoder     { data      };

    // std::array<uint8_t, 4096>   out_data;
    // pgp::packet                 packet      { decoder   };
    // pgp::encoder                encoder     { out_data  };

    // packet.encode(encoder);

    // std::cout << "Wrote packet with tag " << pgp::packet_tag_description(packet.tag()) << " and " << encoder.size() << " bytes to encoder" << std::endl;

    // std::ofstream               outfile     { "/home/martijn/newkey"    };

    // outfile.write(reinterpret_cast<const char*>(out_data.data()), encoder.size());

    while (!decoder.empty()) {
        pgp::packet     packet          { decoder                           };

        std::cout << "Packet has tag: " << pgp::packet_tag_description(packet.tag()) << std::endl;

        if (packet.tag() == pgp::packet_tag::public_key) {
            auto &key = mpark::get<pgp::public_key>(packet.body());

            std::cout << "Found public key created at " << key.creation_time() << std::endl;
            std::cout << "Key type: " << pgp::key_algorithm_description(key.algorithm()) << std::endl;
        } else if (packet.tag() == pgp::packet_tag::secret_key) {
            auto &key = mpark::get<pgp::secret_key>(packet.body());

            std::cout << "Found secret key created at " << key.creation_time() << std::endl;
            std::cout << "Key type: " << pgp::key_algorithm_description(key.algorithm()) << std::endl;
        }
    }
}
