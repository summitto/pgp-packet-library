#pragma once

#include "multiprecision_integer.h"
#include "rsa_signature_encoder.h"
#include "secret_key.h"


namespace pgp {

    /**
     *  Class for holding RSA signature-specific signature fields
     */
    class rsa_signature
    {
        public:
            using encoder_t = rsa_signature_encoder;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            rsa_signature(decoder &parser) :
                _s{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  s       The signature value (m**d mod n)
             */
            rsa_signature(multiprecision_integer s) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const rsa_signature &other) const noexcept;
            bool operator!=(const rsa_signature &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the signature value
             *
             *  @return The signature value (m**d mod n)
             */
            const multiprecision_integer &s() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode the signature
                _s.encode(writer);
            }
        private:
            multiprecision_integer  _s;     // the signature value (m**d mod n);
    };

}
