#pragma once

#include "decoder.h"


namespace pgp {

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
             *  Constructor
             */
            unknown_key() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            unknown_key(decoder &parser) noexcept {};

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
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // unknown key cannot be encoded
                throw std::runtime_error{ "Failed to encode unknown key" };
            }

            /**
             *  Push the key to the hasher
             *
             *  @param  hasher  The hasher to push the value to
             */
            template <class hasher_t>
            void hash(hasher_t &hasher) const
            {
                // unknown key cannot be hashed
                throw std::runtime_error{ "Failed to hash unknown key" };
            }
    };

}
