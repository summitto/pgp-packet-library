#pragma once

#include "ecdh_public_key.h"


namespace pgp {

    /**
     *  Class for working with an ECDH secret key
     */
    class ecdh_secret_key : public ecdh_public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            ecdh_secret_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  curve           The curve object identifier
             *  @param  Q               The public curve point Q
             *  @param  hash_function   The used KDF hash function
             *  @param  algorithm       The symmetric alforithm for wrapping the symmetric key
             *  @param  k               The secret scalar for the public point
             */
            ecdh_secret_key(curve_oid curve, multiprecision_integer Q, uint8_t hash_function, uint8_t algorithm, multiprecision_integer k) noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the secret scalar
             *
             *  @return The secret scalar for the public point
             */
            const multiprecision_integer &k() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            multiprecision_integer  _k;     // the secret scalar for the public point
    };

}
