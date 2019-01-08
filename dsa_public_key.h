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
             *  The public key type we belong to
             */
            using public_key_t = dsa_public_key;

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
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // encode all the integers
                _p.encode(writer);
                _q.encode(writer);
                _g.encode(writer);
                _y.encode(writer);
            }

            /**
             *  Push the key to the hasher
             *
             *  @param  hasher  The hasher to push the value to
             */
            template <class hasher_t>
            void hash(hasher_t &hasher) const noexcept
            {
                // hash all the fields
                _p.hash(hasher);
                _q.hash(hasher);
                _g.hash(hasher);
                _y.hash(hasher);
            }
        private:
            multiprecision_integer  _p;     // the prime
            multiprecision_integer  _q;     // the group order
            multiprecision_integer  _g;     // the generator
            multiprecision_integer  _y;     // g**x mod p (x is secret)
    };

}
