#pragma once

#include "decoder.h"
#include "encoder.h"


namespace pgp {

    /**
     *  Class representing a key using an unknown algorithm
     */
    class unknown_key
    {
        public:
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
            void encode(encoder &writer) const
            {
                // unknown key cannot be encoded
                throw std::runtime_error{ "Failed to encode unknown key" };
            }
    };

}
