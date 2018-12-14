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

    std::cout << "Starting the decoder with " << data.size() << " bytes" << std::endl;

    pgp::decoder    decoder     { data      };
    pgp::packet     packet      { decoder   };
    pgp::public_key source_key  { decoder   };

    std::cout << "Have public key packet version " << (int)source_key.version() << ", created at " << source_key.creation_time() << std::endl;
    std::cout << "The public key uses algorithm " << (int)source_key.algorithm() << " and has " << source_key.components().size() << " components" << std::endl;
    std::cout << "The operation consumed " << (data.size() - decoder.size()) << " bytes" << std::endl;

    return 0;

    std::array<uint8_t, 4096>   output;
    pgp::encoder                encoder { output                                                                        };
    pgp::packet                 result  { packet.tag(), packet.size()                                                   };
    pgp::public_key             pubkey  { source_key.creation_time(), source_key.algorithm(), source_key.components()   };

    result.encode(encoder);
    pubkey.encode(encoder);

    std::cout << "Encoding the new packet results in " << encoder.size() << " bytes" << std::endl;

    std::ofstream               newfile { "/home/martijn/newkey" };

    newfile.write(reinterpret_cast<const char*>(output.data()), encoder.size());
}
