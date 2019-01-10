#pragma once

#include "curve_oid.h"
#include "fixed_number.h"
#include "expected_number.h"
#include "multiprecision_integer.h"


namespace pgp {

    /**
     *  Class holding public-key information for ecdh keys
     */
    class ecdh_public_key
    {
        public:
            /**
             *  The public key type we belong to
             */
            using public_key_t = ecdh_public_key;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            ecdh_public_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  curve           The curve object identifier
             *  @param  Q               The public curve point Q
             *  @param  hash_function   The used KDF hash function
             *  @param  algorithm       The symmetric alforithm for wrapping the symmetric key
             */
            ecdh_public_key(curve_oid curve, multiprecision_integer Q, uint8_t hash_function, uint8_t algorithm) noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the curve object identifier
             *
             *  @return The curve object identifier
             */
            const curve_oid &curve() const noexcept;

            /**
             *  Retrieve the public curve point Q
             *
             *  @return The public curve point Q, in compressed format
             */
            const multiprecision_integer &Q() const noexcept;

            /**
             *  Retrieve the KDF hash function
             *
             *  @return The KDF hash function
             */
            uint8_t hash_function() const noexcept;

            /**
             *  Retrieve the symmetric algorithm
             *
             *  @return The symmetrict algorithm for wrapping the symmetric key
             */
            uint8_t algorithm() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // add all the parts to the writer
                _curve.encode(writer);
                _Q.encode(writer);
                _kdf_size.encode(writer);
                _reserved.encode(writer);
                _hash_function.encode(writer);
                _algorithm.encode(writer);
            }
        private:
            curve_oid                   _curve;         // the curve oid for this key
            multiprecision_integer      _Q;             // the public key
            expected_number<uint8_t, 3> _kdf_size;      // the - totally useless - size of the fields below
            expected_number<uint8_t, 1> _reserved;      // some reserved field
            uint8                       _hash_function; // the used KDF hash function
            uint8                       _algorithm;     // the symmetric algorithm for wrapping the symmetric key
    };

}
