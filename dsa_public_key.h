#pragma once

#include "multiprecision_integer.h"
#include "packet_tag.h"


namespace pgp {

    /**
     *  Class for holding DSA public key data
     */
    class dsa_public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            dsa_public_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  p   The prime p
             *  @param  q   The group order q
             *  @param  g   The generator g
             *  @param  y   The public key value
             */
            dsa_public_key(multiprecision_integer p, multiprecision_integer q, multiprecision_integer g, multiprecision_integer y) noexcept;

            /**
             *  Retrieve the packet tag used for this
             *  key type
             *  @return The packet type to use
             */
            static constexpr packet_tag tag() noexcept
            {
                // this is a public key
                return packet_tag::public_key;
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the prime p
             *
             *  @return The prime number p
             */
            const multiprecision_integer &p() const noexcept;

            /**
             *  Retrieve the group order q
             *
             *  @return The group number q
             */
            const multiprecision_integer &q() const noexcept;

            /**
             *  Retrieve the generator g
             *
             *  @return The generator g
             */
            const multiprecision_integer &g() const noexcept;

            /**
             *  Retrieve the public key value
             *
             *  @return The public key value: g**x mod p
             */
            const multiprecision_integer &y() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            multiprecision_integer  _p;     // the prime
            multiprecision_integer  _q;     // the group order
            multiprecision_integer  _g;     // the generator
            multiprecision_integer  _y;     // g**x mod p (x is secret)
    };

}
