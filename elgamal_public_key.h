#pragma once

#include "multiprecision_integer.h"
#include "packet_tag.h"


namespace pgp {

    /**
     *  Class for holding an elgamal key
     */
    class elgamal_public_key
    {
        public:
            /**
             *  The public key type we belong to
             */
            using public_key_t = elgamal_public_key;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data from
             */
            elgamal_public_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  p       The prime p
             *  @param  g       The group generator g
             *  @param  y       The public key value: g**x mod p
             */
            elgamal_public_key(multiprecision_integer p, multiprecision_integer g, multiprecision_integer y) noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the the prime
             *
             *  @return The prime p
             */
            const multiprecision_integer p() const noexcept;

            /**
             *  Retrieve the group generator g
             *
             *  @return The group generator g
             */
            const multiprecision_integer g() const noexcept;

            /**
             *  Retrieve the public key value
             *
             *  @return The public key value
             */
            const multiprecision_integer y() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;

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
                _g.hash(hasher);
                _y.hash(hasher);
            }
        private:
            multiprecision_integer  _p;     // the prime p
            multiprecision_integer  _g;     // the group generator g
            multiprecision_integer  _y;     // the public key value: g**x mod p
    };

}
