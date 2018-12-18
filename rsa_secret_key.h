#include "rsa_public_key.h"


namespace pgp {

    /**
     *  Class holding an RSA secret key
     */
    class rsa_secret_key : public rsa_public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            rsa_secret_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  n   The public modulus n
             *  @param  e   The encryption exponent e
             *  @param  d   The secret exponent d
             *  @param  p   The secret prime value p
             *  @param  q   The secret prime value q
             *  @param  u   The multiplicative inverse p mod q
             */
            rsa_secret_key(multiprecision_integer n, multiprecision_integer e, multiprecision_integer d, multiprecision_integer p, multiprecision_integer q, multiprecision_integer u) noexcept;

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
            void encode(encoder &writer) const;
        private:
             multiprecision_integer     _d;     // the secret exponent d
             multiprecision_integer     _p;     // the secret prime value p
             multiprecision_integer     _q;     // the secret prime value q
             multiprecision_integer     _u;     // the multiplicative inverse p mod q
    };

}
