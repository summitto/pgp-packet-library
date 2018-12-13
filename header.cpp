#include "header.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @note   The given span is modified so that the start
     *          points to the first byte inside the body.
     *
     *  @param  data    The encoded data to parse
     *  @throws TODO
     */
    header::header(gsl::span<const uint8_t> &data)
    {
        // we cannot except empty packages
        if (data.empty()) {
            // there is nothing to decode, this is not a valid packet
            throw std::runtime_error{ "Empty packet received" };
        }

        // check whether the required header bit is set
        if ((data[0] & HEADER_TAG_REQUIRED_TRUE_BIT) == 0) {
            // a bit that is required to be set is not set
            throw std::runtime_error{ "Required header tag bit not set"};
        }

        // are we dealing with a header encoded using the old- or new format
        if (data[0] & HEADER_TAG_NEW_PACKET_FORMAT) {
            // use the six least-significant bits for the packet tag
            _type = data[0] & 0b00111111;

            // if the two upper bits are not set we have a single-byte size
            if ((data[1] & 0b11000000) == 0) {
                // return the first byte as-is
                _size = data[1];
            } else if ((data[1] & 0b11100000) == 0) {
                // ignore the two upper bits and join it with the next byte
                _size = ((data[1] & 0b00111111) << 8) + data[2];
            } else if (data[1] == 255) {
                // the length is made up of four bytes - just a regular uint32_t
                _size = (data[2] << 24) + (data[3] << 16) + (data[4] << 8) + data[5];
            } else {
                // we don't support partial-length bodies
                throw std::runtime_error{ "Partial-Length bodies are not supported" };
            }
        } else {
            // mask the leading and trailing two bits
            _type = (data[0] & 0b00111100) >> 2;

            // retrieve the length type (stored in the two least-significant bits)
            auto length_type = data[0] & 0b00000011;

            // what length type are we using?
            switch (length_type) {
                case 0:
                    // the length is a single-byte (8-bit) integer
                    _size = data[1];
                    break;
                case 1:
                    // the length is made up of two bytes
                    _size = (data[1] << 8) + data[2];
                    break;
                case 2:
                    // the length is made up of four bytes
                    _size = (data[1] << 24) + (data[2] << 16) + (data[3] << 8) + data[4];
                    break;
                default:
                    // no length is known
                    break;
            }
        }
    }

    /**
     *  Constructor
     *
     *  @param  type    The packet tag
     *  @param  size    The number of bytes in the body
     */
    header::header(uint8_t type, uint32_t size) noexcept :
        _type{ type },
        _size{ size }
    {}

    /**
     *  Retrieve the packet tag
     *  @return The packet tag set in the header
     */
    uint8_t header::type() const noexcept
    {
        // return the stored type
        return _type;
    }

    /**
     *  Change the packet tag type
     *  @param  type    The new packet tag
     */
    void header::set_type(uint8_t type) noexcept
    {
        // store the new type
        _type = type;
    }

    /**
     *  Retrieve the body size
     *  @return The number of bytes inside the body
     */
    uint32_t header::size() const noexcept
    {
        // return the stored size
        return _size;
    }

    /**
     *  Set the body size
     *  @param  size    The new body size to store
     */
    void header::set_size(uint32_t size) noexcept
    {
        // store the new size
        _size = size;
    }

    /**
     *  Encode the header to a given range
     *
     *  @param  output  The variable to write to
     *  @return Iterator past the last written byte
     *  @throws std::out_of_range if the range is too small to write the header
     *  @throws std::length_error if no length is known and it cannot be encoded
     */
    auto header::encode(gsl::span<uint8_t> output) -> decltype(output.begin())
    {
        // retrieve iterator to first and last bytes
        auto first = std::begin(output);
        auto last  = std::end(output);

        // we should be able to write data
        if (first == last) {
            // we cannot write a single byte
            throw std::out_of_range{ "Cannot encode header: no space in iterator" };
        }

        // we cannot have a zero-length in a new package format, and if the
        // packet tag exceeds 15 we cannot use the old format
        if (type() > 15 && size() == 0) {
            // incompatible features detected
            throw std::length_error{ "No compatible encoding is found for an unknown length" };
        }

        // we prefer to use the old encoding where possible
        if (type() < 16) {
            // the base message containing the always-on bit and the unset new-message-format flag
            uint8_t header = 0b10000000;

            // add the packet tag to the header
            header |= type() << 2;

            // now add the length type - providing the header length
            if      (size() == 0)       header |= 3;
            else if (size() < 256)      header |= 0;
            else if (size() < 65536)    header |= 1;
            else                        header |= 2;

            // write out the first header byte
            *first++ = header;

            // write out the actual length
            // if (size() > 65535) *first
        } else {
        }

        // TODO: This could be implemented better!
        return first;
    }

}
