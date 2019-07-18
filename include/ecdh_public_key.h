#pragma once

#include "curve_oid.h"
#include "hash_algorithm.h"
#include "expected_number.h"
#include "multiprecision_integer.h"
#include "symmetric_key_algorithm.h"


namespace pgp {

    // Forward declaration to prevent header dependency cycles
    class unknown_signature;

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
             *  The signature type corresponding to this key type
             *
             *  TODO: no ecdh signature class yet
             */
            using signature_t = unknown_signature;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            ecdh_public_key(decoder &parser) :
                _curve{ parser },
                _Q{ parser },
                _kdf_size{ parser },
                _reserved{ parser },
                _hash_function{ parser.template extract_number<uint8_t>() },
                _algorithm{ parser.template extract_number<uint8_t>() }
            {}

            /**
             *  Constructor
             *
             *  @param  curve           The curve object identifier
             *  @param  Q               The public curve point Q
             *  @param  hash_function   The used KDF hash function
             *  @param  algorithm       The symmetric alforithm for wrapping the symmetric key
             */
            ecdh_public_key(curve_oid curve, multiprecision_integer Q, hash_algorithm hash_function, symmetric_key_algorithm algorithm) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const ecdh_public_key &other) const noexcept;
            bool operator!=(const ecdh_public_key &other) const noexcept;

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
            hash_algorithm hash_function() const noexcept;

            /**
             *  Retrieve the symmetric key algorithm
             *
             *  @return The symmetrict key algorithm
             */
            symmetric_key_algorithm algorithm() const noexcept;

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
                writer.push(_hash_function);
                writer.push(_algorithm);
            }
        private:
            curve_oid                   _curve;         // the curve oid for this key
            multiprecision_integer      _Q;             // the public key
            expected_number<uint8_t, 3> _kdf_size;      // the - totally useless - size of the fields below
            expected_number<uint8_t, 1> _reserved;      // some reserved field
            hash_algorithm              _hash_function; // the used KDF hash function
            symmetric_key_algorithm     _algorithm;     // the symmetric algorithm for wrapping the symmetric key
    };

}
