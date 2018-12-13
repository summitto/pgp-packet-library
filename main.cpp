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
    std::vector<gsl::byte> data;

    if (!file) {
        std::cerr << "Failed to open '" << argv[1] << "' for reading" << std::endl;
        return 1;
    }

    while (!std::feof(file)) {
        gsl::byte buffer[4096];

        auto count = std::fread(buffer, 1, sizeof buffer, file);

        data.reserve(data.size() + count);
        std::copy(buffer, buffer + count, std::back_inserter(data));
    }

    pgp::packet packet{ data };

    std::cout << "Packet is of type " << (uint16_t)packet.type() << std::endl;

    auto size = packet.size();

    if (size) {
        std::cout << "Packet has a body size of " << *size << " bytes" << std::endl;
    } else {
        std::cout << "No size known" << std::endl;
    }
}
