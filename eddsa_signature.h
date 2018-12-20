#pragma once

#include "multiprecision_integer.h"


namespace pgp {

    /**
     *  Class for holding EdDSA signature-specific fields
     */
    class eddsa_signature
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            eddsa_signature(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  r       The EdDSA r value
             *  @param  s       The EdDSA s value
             */
            eddsa_signature(multiprecision_integer r, multiprecision_integer s) noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the EdDSA r value
             *
             *  @return The r value
             */
            const multiprecision_integer &r() const noexcept;

            /**
             *  Retrieve the EdDSA s value
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
            void encode(encoder &writer) const;
        private:
            multiprecision_integer  _r;     // the EdDSA r value
            multiprecision_integer  _s;     // the EdDSA s value
    };

}
