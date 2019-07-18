#pragma once

#include "rsa_public_key.h"


namespace pgp {

    /**
     *  Class holding an RSA secret key
     */
    class rsa_secret_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            rsa_secret_key(decoder &parser) :
                _d{ parser },
                _p{ parser },
                _q{ parser },
                _u{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  d   The secret exponent d
             *  @param  p   The secret prime value p
             *  @param  q   The secret prime value q
             *  @param  u   The multiplicative inverse p mod q
             */
            rsa_secret_key(multiprecision_integer d, multiprecision_integer p, multiprecision_integer q, multiprecision_integer u) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const rsa_secret_key &other) const noexcept;
            bool operator!=(const rsa_secret_key &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the secret exponent d
             *
             *  @return The secret exponent
             */
            const multiprecision_integer &d() const noexcept;

            /**
             *  Retrieve the secret prime value p
             *
             *  @return The secret prime value p
             */
            const multiprecision_integer &p() const noexcept;

            /**
             *  Retrieve the secret prime value q
             *
             *  @return The secret prime value q
             */
            const multiprecision_integer &q() const noexcept;

            /**
             *  Retrieve the u value
             *
             *  @return The multiplicative inverse of p mod q
             */
            const multiprecision_integer &u() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode all the secret fields
                _d.encode(writer);
                _p.encode(writer);
                _q.encode(writer);
                _u.encode(writer);
            }
        private:
             multiprecision_integer     _d;     // the secret exponent d
             multiprecision_integer     _p;     // the secret prime value p
             multiprecision_integer     _q;     // the secret prime value q
             multiprecision_integer     _u;     // the multiplicative inverse p mod q
    };

}
