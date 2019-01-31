#pragma once

#include "multiprecision_integer.h"
#include "packet_tag.h"
#include "curve_oid.h"


namespace pgp {

    /**
     *  Class for holding an ECDSA public key
     */
    class ecdsa_public_key
    {
        public:
            /**
             *  The public key type we belong to
             */
            using public_key_t = ecdsa_public_key;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            ecdsa_public_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  curve   The curve object identifier
             *  @param  Q       The public curve point Q
             */
            ecdsa_public_key(curve_oid curve, multiprecision_integer Q) noexcept;

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
