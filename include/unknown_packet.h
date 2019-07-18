#pragma once

#include "decoder_traits.h"
#include "packet_tag.h"


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
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            unknown_packet(decoder&) {}

            /**
             *  Comparison operators
             */
            bool operator==(const unknown_packet&) const noexcept
            {
                return true;
            }

            /**
             *  Comparison operators
             */
            bool operator!=(const unknown_packet &other) const noexcept
            {
                return !operator==(other);
            }

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
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t&) const
            {
                // unknown packets cannot be encoded
                throw std::runtime_error{ "Failed to encode unknown packet" };
            }
    };

}
