#pragma once

#include "multiprecision_integer.h"
#include "packet_tag.h"
#include "curve_oid.h"


namespace pgp {

    // Forward declaration to prevent header dependency cycles
    class eddsa_signature;

    /**
     *  Class for holding an EdDSA public key
     */
    class eddsa_public_key
    {
        public:
            /**
             *  The public key type we belong to
             */
            using public_key_t = eddsa_public_key;

            /**
             *  The signature type corresponding to this key type
             */
            using signature_t = eddsa_signature;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            eddsa_public_key(decoder &parser) :
                _curve{ parser },
                _Q{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  curve   The curve object identifier
             *  @param  Q       The public curve point Q
             */
            eddsa_public_key(curve_oid curve, multiprecision_integer Q) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const eddsa_public_key &other) const noexcept;
            bool operator!=(const eddsa_public_key &other) const noexcept;

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
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode the curve id and public point
                _curve.encode(writer);
                _Q.encode(writer);
            }
        private:
            curve_oid               _curve; // the curve object identifier
            multiprecision_integer  _Q;     // the public curve point
    };

}
