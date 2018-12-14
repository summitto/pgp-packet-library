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
            _tag = packet_tag{ parser.extract_bits(6) };

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
            _tag = packet_tag{ parser.extract_bits(4) };

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
     *  Constructor
     *
     *  @param  tag     The packet tag
     *  @param  size    The size of the body
     *  @throws std::runtime_error
     */
    packet::packet(packet_tag tag, boost::optional<size_t> size) :
        _tag{ tag },
        _size{ size }
    {
        // check whether the size is given, and if not
        // if the tag is compatible with the old format
        if (!size && !packet_tag_compatible_with_old_format(tag)) {
            // this scenario is not possible
            throw std::runtime_error{ "Unspecified size incompatible with newer packet tags" };
        }
    }

    /**
     *  Retrieve the packet tag
     *  @return The packet tag, as described in https://tools.ietf.org/html/rfc4880#section-4.3
     */
    packet_tag packet::tag() const noexcept
    {
        // return the pre-parsed type
        return _tag;
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

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void packet::encode(encoder &writer) const
    {
        // write the required bit
        writer.insert_bits(1, 1);

        // can we encode the packet in the old format?
        if (packet_tag_compatible_with_old_format(_tag)) {
            // we are using the old packet format
            writer.insert_bits(1, 0);
            writer.insert_bits(4, static_cast<typename std::underlying_type_t<packet_tag>>(_tag));

            // do we know the size? determine the right storage type
            if (_size && *_size > 65535) {
                // we are using a 4-octet length field
                writer.insert_bits(2, 2);
                writer.insert_number(static_cast<uint32_t>(*_size));
            } else if (_size && *_size > 255) {
                // we are using a 2-octet length field
                writer.insert_bits(2, 1);
                writer.insert_number(static_cast<uint16_t>(*_size));
            } else if (_size) {
                // it fits in a single octet
                writer.insert_bits(2, 0);
                writer.insert_number(static_cast<uint8_t>(*_size));
            } else {
                // no length is known
                writer.insert_bits(2, 3);
            }
        } else {
            // we are using the new packet format
            writer.insert_bits(1, 1);

            // not supported yet
            throw std::runtime_error{ "Uh-oh, not implemented yet" };
        }
    }

}
