#include <pgp-packet/packet.h>
#include <sodium.h>
#include <iostream>
#include <cassert>
#include <vector>

int main()
{
    // initialize libsodium
    if (sodium_init() == -1) {
        return 1;
    }

    // create our simple user id packet
    pgp::packet packet{
        pgp::in_place_type_t<pgp::user_id>{},
        std::string{ "Anne Onymous <anonymous@example.org>" }
    };

    // create a buffer for storing the binary data - we allocate the
    // exact number of bytes the packet requests, and then we create
    // a range_encoder around it. the range_encoder works by writing
    // the raw data to a provided range of bytes, which must stay in
    // scope during the encoder operation.
    pgp::vector<uint8_t> data;
    data.resize(packet.size());

    // write out the packet data to the given buffer
    packet.encode(pgp::range_encoder{ data });

    // now create a decoder to decode the freshly filled data buffer
    // and use this decoder to create a second packet containing the
    // same user id body with the exact same data
    pgp::decoder decoder{ data };
    pgp::packet  copied_packet{ decoder };

    // the packets should be identical
    assert(packet == copied_packet);

    return 0;
}
