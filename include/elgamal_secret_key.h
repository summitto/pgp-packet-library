#pragma once

#include "elgamal_public_key.h"


namespace pgp {

    /**
     *  Class for holding an elgamal secret key
     */
    class elgamal_secret_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data from
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            elgamal_secret_key(decoder &parser) :
                _x{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  x       The secret exponent x
             */
            elgamal_secret_key(multiprecision_integer x) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const elgamal_secret_key &other) const noexcept;
            bool operator!=(const elgamal_secret_key &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the secret exponent
             *
             *  @return The secret exponent x
             */
            const multiprecision_integer &x() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode the secret exponent
                _x.encode(writer);
            }
                private:
            multiprecision_integer  _x;     // the secret exponent x
    };

}
