#pragma once

#include "decoder_traits.h"


namespace pgp {

    // Forward declaration to prevent header dependency cycles
    class unknown_signature;

    /**
     *  Class representing a key using an unknown algorithm
     */
    class unknown_key
    {
        public:
            /**
             *  The public key type we belong to
             */
            using public_key_t = unknown_key;

            /**
             *  The signature type corresponding to this key type
             */
            using signature_t = unknown_signature;

            /**
             *  Constructor
             */
            unknown_key() = default;

            /**
             *  Constructor
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            unknown_key(decoder&) noexcept {}

            /**
             *  Comparison operators
             */
            bool operator==(const unknown_key&) const noexcept
            {
                return true;
            }

            /**
             *  Comparison operators
             */
            bool operator!=(const unknown_key &other) const noexcept
            {
                return !operator==(other);
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             *  @throws std::runtime_error for the unknown key
             */
            size_t size() const
            {
                // we do not know the size
                throw std::runtime_error{ "Unknown keys have an unknown size" };
            }

            /**
             *  Hash the key into a given hash context
             */
            template <class encoder_t>
            void hash(encoder_t &) const noexcept
            {
                // unknown key cannot be hashed
                throw std::runtime_error{ "Unknown keys cannot be hashed" };
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
                throw std::runtime_error{ "Failed to encode unknown key" };
            }
    };

}
