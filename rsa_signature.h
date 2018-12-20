#pragma once

#include "multiprecision_integer.h"


namespace pgp {

    /**
     *  Class for holding RSA signature-specific signature fields
     */
    class rsa_signature
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            rsa_signature(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  s       The signature value (m**d mod n)
             */
            rsa_signature(multiprecision_integer s) noexcept;

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
            void encode(encoder &writer) const;
        private:
            multiprecision_integer  _s;     // the signature value (m**d mod n);
    };

}
