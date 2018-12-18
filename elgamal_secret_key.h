#pragma once

#include "elgamal_public_key.h"


namespace pgp {

    /**
     *  Class for holding an elgamal secret key
     */
    class elgamal_secret_key : public elgamal_public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data from
             */
            elgamal_secret_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  p       The prime p
             *  @param  g       The group generator g
             *  @param  y       The public key value: g**x mod p
             *  @param  x       The secret exponent x
             */
            elgamal_secret_key(multiprecision_integer p, multiprecision_integer g, multiprecision_integer y, multiprecision_integer x) noexcept;

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
            void encode(encoder &writer) const;
        private:
            multiprecision_integer  _x;     // the secret exponent x
    };

}
