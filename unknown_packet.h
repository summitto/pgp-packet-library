#include "packet_tag.h"
#include "decoder.h"
#include "encoder.h"


namespace pgp {

    /**
     *  A packet used when the packet tag is not supported
     *  or if it is an unknown packet altogether.
     */
    class unknown_packet
    {
        public:
            /**
             *  Constructor
             */
            unknown_packet() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            unknown_packet(decoder &parser) {}

            /**
             *  Retrieve the packet tag used for this
             *  packet type
             *  @return The packet type to use
             */
            static constexpr packet_tag tag() noexcept
            {
                // an unknown packet has no tag
                return packet_tag::reserved;
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             *  @throws std::runtime_error
             */
            size_t size() const
            {
                // we don't have a known size
                throw std::runtime_error{ "Unknown packet does not have a known size" };
            }

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const
            {
                // unknown packets cannot be encoded
                throw std::runtime_error{ "Failed to encode unknown packet" };
            }
    };

}
