#pragma once

#include "multiprecision_integer.h"
#include "dsa_signature_encoder.h"
#include "secret_key.h"
#include <tuple>


namespace pgp {

    /**
     *  Class for holding DSA signature-specific fields
     */
    class dsa_signature
    {
        public:
            using encoder_t = dsa_signature_encoder;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            dsa_signature(decoder &parser) :
                _r{ parser },
                _s{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  r       The DSA r value
             *  @param  s       The DSA s value
             */
            dsa_signature(multiprecision_integer r, multiprecision_integer s) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const dsa_signature &other) const noexcept;
            bool operator!=(const dsa_signature &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the DSA r value
             *
             *  @return The r value
             */
            const multiprecision_integer &r() const noexcept;

            /**
             *  Retrieve the DSA s value
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
            multiprecision_integer  _r;     // the DSA r value
            multiprecision_integer  _s;     // the DSA s value
    };

}
