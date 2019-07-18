#pragma once

#include "ecdsa_signature_encoder.h"
#include "multiprecision_integer.h"
#include "secret_key.h"


namespace pgp {

    /**
     *  Class for holding ECDSA signature-specific fields
     */
    class ecdsa_signature
    {
        public:
            using encoder_t = ecdsa_signature_encoder;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            ecdsa_signature(decoder &parser) :
                _r{ parser },
                _s{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  r       The ECDSA r value
             *  @param  s       The ECDSA s value
             */
            ecdsa_signature(multiprecision_integer r, multiprecision_integer s) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const ecdsa_signature &other) const noexcept;
            bool operator!=(const ecdsa_signature &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the ECDSA r value
             *
             *  @return The r value
             */
            const multiprecision_integer &r() const noexcept;

            /**
             *  Retrieve the ECDSA s value
             *
             *  @return The s value
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
                // encode both values
                _r.encode(writer);
                _s.encode(writer);
            }
        private:
            multiprecision_integer  _r;     // the ECDSA r value
            multiprecision_integer  _s;     // the ECDSA s value
    };

}
