#include <gsl/span>
#include <stdexcept>
#include <boost/optional.hpp>


namespace pgp {

    /**
     *  Class for working with a single packet encoded
     *  according to the specification in RFC 4880
     *  @see: https://tools.ietf.org/html/rfc4880#section-4
     */
    class packet
    {
        public:
            /**
             *  Constructor
             *
             *  @param  data    The encoded data to parse
             *  @throws TODO
             */
            packet(gsl::span<const gsl::byte> data);

            /**
             *  Retrieve the packet type
             *  @return The packet type, as described in TODO
             */
            uint8_t type() const noexcept;

            /**
             *  Retrieve the body length
             *
             *  @note   If the body length is unknown, no size will be returned
             *  @return The number of bytes in the body of the packet
             */
            boost::optional<size_t> size() const noexcept;
        private:
            /**
             *  Is the packet encoded in the new packet format?
             *  @return True for new packet format, false for old packet format
             */
            bool is_new_packet_format() const noexcept;

            /**
             *  Retrieve numeric data at a specific offset
             *
             *  @param  offset  The offset to read at
             *  @return The numeric data at the given offset
             */
            template <typename T>
            T to_number(size_t offset) const noexcept;

            /**
             *  Retrieve numeric data in a specific format
             *  at the given offset
             *
             *  @param  offset  The offset to read at
             *  @return The numeric data at the given offset
             */
            uint8_t to_uint8_t(size_t offset) const noexcept;
            int8_t to_int8_t(size_t offset) const noexcept;

            gsl::span<const gsl::byte>   _data;  // the encoded data inside the packet
    };

}
