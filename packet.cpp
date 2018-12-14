#include "packet.h"
#include <arpa/inet.h>
#include <cstring>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     *  @throws TODO
     */
    packet::packet(decoder &parser)
    {
        // check whether we have the required true bit
        if (!parser.extract_bits(1)) {
            // a bit that is required to be set is not set
            throw std::runtime_error{ "Invalid packet: Required header tag bit not set"};
        }

        // is this a packet using the new formatting?
        if (parser.extract_bits(1)) {
            // extract packet type
            _type = packet_tag{ parser.extract_bits(6) };

            // peek at the number to determine the size of the body length
            if (parser.peek_number<uint8_t>() < 192) {
                // just a regular single-octet number
                _size = parser.extract_number<uint8_t>();
            } else if (parser.peek_number<uint8_t>() < 224) {
                // it's a two-octet number, remove upper two bits
                // and append 192 to get to the correct number
                _size = (parser.extract_number<uint16_t>() & 0b0011111111111111) + 192;
            } else if (parser.peek_number<uint8_t>() == 255) {
                // simple four-octet number
                _size = parser.extract_number<uint32_t>();
            } else {
                // error: we don't support par
                throw std::runtime_error{ "Partial body length not implemented" };
            }
        } else {
            // extract packet type
            _type = packet_tag{ parser.extract_bits(4) };

            // what length type do we have
            switch (parser.extract_bits(2)) {
                case 0: _size = parser.extract_number<uint8_t>();   break;
                case 1: _size = parser.extract_number<uint16_t>();  break;
                case 2: _size = parser.extract_number<uint32_t>();  break;
                case 3:  /* no size is known */                     break;
            }
        }
    }

    /**
     *  Retrieve the packet type
     *  @return The packet type, as described in TODO
     */
    packet_tag packet::type() const noexcept
    {
        // return the pre-parsed type
        return _type;
    }

    /**
     *  Retrieve the body length
     *
     *  @note   If the body length is unknown, no size will be returned
     *  @return The number of bytes in the body of the packet
     */
    boost::optional<size_t> packet::size() const noexcept
    {
        // return the stored size
        return _size;
    }

}
