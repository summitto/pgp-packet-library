#pragma once

#include "ecdh_public_key.h"
#include "basic_secret_key.h"


namespace pgp {

    /**
     *  Class for working with an ECDH secret key
     */
    class ecdh_secret_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            ecdh_secret_key(decoder &parser) :
                _k{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  k               The secret scalar for the public point
             */
            ecdh_secret_key(multiprecision_integer k) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const ecdh_secret_key &other) const noexcept;
            bool operator!=(const ecdh_secret_key &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the secret scalar
             *
             *  @return The secret scalar for the public point
             */
            const multiprecision_integer &k() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode the secret scalar
                _k.encode(writer);
            }
        private:
            multiprecision_integer  _k;         // the secret scalar for the public point
    };

}
