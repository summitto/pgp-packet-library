#pragma once

#include "eddsa_public_key.h"


namespace pgp {

    /**
     *  Class for working with an EdDSA secret key
     */
    class eddsa_secret_key : public eddsa_public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            eddsa_secret_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  curve   The curve object identifier
             *  @param  Q       The public curve point Q
             *  @param  k       The secret scalar for the public point
             */
            eddsa_secret_key(curve_oid curve, multiprecision_integer Q, multiprecision_integer k) noexcept;

            /**
             *  Retrieve the packet tag used for this
             *  key type
             *  @return The packet type to use
             */
            static constexpr packet_tag tag() noexcept
            {
                // this is a secret key
                return packet_tag::secret_key;
            }

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
