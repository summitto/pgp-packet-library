#pragma once

#include "multiprecision_integer.h"
#include "packet_tag.h"


namespace pgp {

    /**
     *  Class for holding RSA key data
     */
    class rsa_public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            rsa_public_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  n   The public modulus n
             *  @param  e   The encryption exponent e
             */
            rsa_public_key(multiprecision_integer n, multiprecision_integer e) noexcept;

            /**
             *  Retrieve the packet tag used for this
             *  key type
             *  @return The packet type to use
             */
            static constexpr packet_tag tag() noexcept
            {
                // this is a public key
                return packet_tag::public_key;
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the public modulus n
             *
             *  @return The modulus n for the key
             */
            const multiprecision_integer &n() const noexcept;

            /**
             *  Retrieve the encryption exponent e
             *
             *  @return The encryption exponent e
             */
            const multiprecision_integer &e() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            multiprecision_integer  _n; // the public modulus n
            multiprecision_integer  _e; // the encryption exponent e
    };

}
