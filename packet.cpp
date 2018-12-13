#include "packet.h"
#include <arpa/inet.h>
#include <cstring>


namespace pgp {

    /**
     *  Constants used for reading fields from the header tag
     */
    const uint8_t HEADER_TAG_REQUIRED_TRUE_BIT  = 1 << 7;
    const uint8_t HEADER_TAG_NEW_PACKET_FORMAT  = 1 << 6;

    /**
     *  Constructor
     *
     *  @param  data    The encoded data to parse
     *  @throws TODO
     */
    packet::packet(gsl::span<const gsl::byte> data) :
        _data(data)
    {
        // we cannot except empty packages
        if (_data.empty()) {
            // there is nothing to decode, this is not a valid packet
            throw std::runtime_error{ "Empty packet received" };
        }

        // check whether the required header bit is set
        if ((to_uint8_t(0) & HEADER_TAG_REQUIRED_TRUE_BIT) == 0) {
            // a bit that is required to be set is not set
            throw std::runtime_error{ "Invalid packet: Required header tag bit not set"};
        }
    }

    /**
     *  Retrieve the packet type
     *  @return The packet type, as described in TODO
     */
    uint8_t packet::type() const noexcept
    {
        // new packet use the six least-significant bits from the header tag
        if (is_new_packet_format()) {
            // mask the three leading bits from the tag
            return to_uint8_t(0) & 0b00111111;
        } else {
            // mask the three leading and two trailing bits
            // and throw the trailing bits away
            return (to_uint8_t(0) & 0b00111100) >> 2;
        }
    }

    /**
     *  Retrieve the body length
     *
     *  @note   If the body length is unknown, no size will be returned
     *  @return The number of bytes in the body of the packet
     */
    boost::optional<size_t> packet::size() const noexcept
    {
        // is this encoded using the new format?
        if (is_new_packet_format()) {
            // number up to - and including - 191 are encoded in a single byte
            if (to_uint8_t(1) <= 191) {
                // return the first byte as-is
                return to_uint8_t(1);
            } else if (to_uint8_t(1) <= 223) {
                // subtract something from the first octet and add the second
                // weird stuff, but that's what the standard described
                return ((to_uint8_t(1) - 192) << 8) + to_uint8_t(2);
            } else if (to_uint8_t(1) == 255) {
                // the length is made up of four bytes
                return (to_uint8_t(2) << 24) + (to_uint8_t(3) << 16) + (to_uint8_t(4) << 8) + to_uint8_t(5);
            } else {
                // TODO: support partial-body length
                return {};
            }
        } else {
            // retrieve the length type (stored in the two least-significant bits)
            auto length_type = to_uint8_t(0) & 0b00000011;

            // what length type are we using?
            switch (length_type) {
                case 0:
                    // the length is a single-byte (8-bit) integer
                    return to_uint8_t(1);
                case 1:
                    // the length is made up of two bytes
                    return (to_uint8_t(1) << 8) + to_uint8_t(2);
                case 2:
                    // the length is made up of four bytes
                    return (to_uint8_t(1) << 24) + (to_uint8_t(2) << 16) + (to_uint8_t(3) << 8) + to_uint8_t(4);
                default:
                    // no length is known
                    return {};
            }
        }
    }

    /**
     *  Is the packet encoded in the new packet format?
     *  @return True for new packet format, false for old packet format
     */
    bool packet::is_new_packet_format() const noexcept
    {
        // check whether bit seven is set inside the header tag
        return to_uint8_t(0) & HEADER_TAG_NEW_PACKET_FORMAT;
    }

    /**
     *  Retrieve numeric data at a specific offset
     *
     *  @param  offset  The offset to read at
     *  @return The numeric data at the given offset
     */
    template <typename T>
    T packet::to_number(size_t offset) const noexcept
    {
        // convert the data at the offset to the requested number
        return gsl::to_integer<T>(_data[offset]);
    }

    /**
     *  Retrieve numeric data in a specific format
     *  at the given offset
     *
     *  @param  offset  The offset to read at
     *  @return The numeric data at the given offset
     */
    uint8_t packet::to_uint8_t(size_t offset) const noexcept
    {
        // defer to the number conversion function
        return to_number<uint8_t>(offset);
    }

    /**
     *  Retrieve numeric data in a specific format
     *  at the given offset
     *
     *  @param  offset  The offset to read at
     *  @return The numeric data at the given offset
     */
    int8_t packet::to_int8_t(size_t offset) const noexcept
    {
        // defer to the number conversion function
        return to_number<int8_t>(offset);
    }

}
