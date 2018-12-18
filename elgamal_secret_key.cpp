#include "elgamal_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data from
     */
    elgamal_secret_key::elgamal_secret_key(decoder &parser) :
        elgamal_public_key{ parser },
        _x{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  p       The prime p
     *  @param  g       The group generator g
     *  @param  y       The public key value: g**x mod p
     *  @param  x       The secret exponent x
     */
    elgamal_secret_key::elgamal_secret_key(multiprecision_integer p, multiprecision_integer g, multiprecision_integer y, multiprecision_integer x) noexcept :
        elgamal_public_key{ std::move(p), std::move(g), std::move(y) },
        _x{ std::move(x) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t elgamal_secret_key::size() const noexcept
    {
        // we need the size from the parent plus the size for our secret exponent
        return elgamal_public_key::size() + _x.size();
    }

    /**
     *  Retrieve the secret exponent
     *
     *  @return The secret exponent x
     */
    const multiprecision_integer &elgamal_secret_key::x() const noexcept
    {
        // return the secret exponent
        return _x;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void elgamal_secret_key::encode(encoder &writer) const
    {
        // first encode the parent and then encode our secret exponent
        elgamal_public_key::encode(writer);
        _x.encode(writer);
    }

}
