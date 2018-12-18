#include "dsa_public_key.h"


namespace pgp {

    /**
     *  Class holding a DSA secret key
     */
    class dsa_secret_key : public dsa_public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            dsa_secret_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  p   The prime p
             *  @param  q   The group order q
             *  @param  g   The generator g
             *  @param  y   The public key value
             *  @param  x   The secret exponent
             */
            dsa_secret_key(multiprecision_integer p, multiprecision_integer q, multiprecision_integer g, multiprecision_integer y, multiprecision_integer x) noexcept;

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
             *  Retrieve the secret exponent
             *
             *  @return The secret exponent x
             */
            const multiprecision_integer &x() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            multiprecision_integer  _x;     // the secret exponent x
    };

}
