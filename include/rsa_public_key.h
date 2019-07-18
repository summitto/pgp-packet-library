#pragma once

#include "multiprecision_integer.h"
#include "packet_tag.h"


namespace pgp {

    // Forward declaration to prevent header dependency cycles
    class rsa_signature;

    /**
     *  Class for holding RSA key data
     */
    class rsa_public_key
    {
        public:
            /**
             *  The public key type we belong to
             */
            using public_key_t = rsa_public_key;

            /**
             *  The signature type corresponding to this key type
             */
            using signature_t = rsa_signature;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            rsa_public_key(decoder &parser) :
                _n{ parser },
                _e{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  n   The public modulus n
             *  @param  e   The encryption exponent e
             */
            rsa_public_key(multiprecision_integer n, multiprecision_integer e) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const rsa_public_key &other) const noexcept;
            bool operator!=(const rsa_public_key &other) const noexcept;

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
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode the modulus and the exponent
                _n.encode(writer);
                _e.encode(writer);
            }
        private:
            multiprecision_integer  _n; // the public modulus n
            multiprecision_integer  _e; // the encryption exponent e
    };

}
