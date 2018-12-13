#include <gsl/span>
#include <stdexcept>

namespace pgp {

    /**
     *  Constants used for reading fields from the header tag
     */
    const uint8_t HEADER_TAG_REQUIRED_TRUE_BIT  = 1 << 7;
    const uint8_t HEADER_TAG_NEW_PACKET_FORMAT  = 1 << 6;

    /**
     *  Class dealing with a packet header
     */
    class header
    {
        public:
            /**
             *  Constructor
             *
             *  @note   The given span is modified so that the start
             *          points to the first byte inside the body.
             *
             *  @param  data    The encoded data to parse
             *  @throws TODO
             */
            header(gsl::span<const uint8_t> &data);

            /**
             *  Constructor
             *
             *  @param  type    The packet tag
             *  @param  size    The number of bytes in the body
             */
            header(uint8_t type, uint32_t size) noexcept;

            /**
             *  Retrieve the packet tag
             *  @return The packet tag set in the header
             */
            uint8_t type() const noexcept;

            /**
             *  Change the packet tag type
             *  @param  type    The new packet tag
             */
            void set_type(uint8_t type) noexcept;

            /**
             *  Retrieve the body size
             *  @return The number of bytes inside the body
             */
            uint32_t size() const noexcept;

            /**
             *  Set the body size
             *  @param  size    The new body size to store
             */
            void set_size(uint32_t size) noexcept;

            /**
             *  Encode the header to a given range
             *
             *  @param  output  The variable to write to
             *  @return Iterator past the last written byte
             *  @throws std::out_of_range if the range is too small to write the header
             *  @throws std::length_error if no length is known and it cannot be encoded
             */
            auto encode(gsl::span<uint8_t> output) -> decltype(output.begin());
        private:
            uint8_t     _type   { 0 };  // the packet tag type
            uint32_t    _size   { 0 };  // the size of the body in bytes
    };

}
