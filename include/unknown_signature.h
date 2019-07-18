#pragma once

#include "unknown_signature_encoder.h"
#include "decoder_traits.h"
#include "secret_key.h"
#include <stdexcept>


namespace pgp {

    /**
     *  Class for holding an unknown signature
     */
    class unknown_signature
    {
        public:
            using encoder_t = unknown_signature_encoder;

            /**
             *  Constructor
             */
            unknown_signature() = default;

            /**
             *  Constructor
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            unknown_signature(decoder&) noexcept {}

            /**
             *  Comparison operators
             */
            bool operator==(const unknown_signature&) const noexcept
            {
                return true;
            }

            /**
             *  Comparison operators
             */
            bool operator!=(const unknown_signature &other) const noexcept
            {
                return !operator==(other);
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const
            {
                // we do not know the size
                throw std::runtime_error{ "Unknown signatures have an unknown size" };
            }

            /**
             *  Write the data to an encoder
             *
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t&) const
            {
                // unknown key cannot be encoded
                throw std::runtime_error{ "Failed to encode unknown signature" };
            }
    };

}
