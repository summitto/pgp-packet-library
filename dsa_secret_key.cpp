#include "dsa_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    dsa_secret_key::dsa_secret_key(decoder &parser) :
        dsa_public_key{ parser },
        _x{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  p   The prime p
     *  @param  q   The group order q
     *  @param  g   The generator g
     *  @param  y   The public key value
     *  @param  x   The secret exponent
     */
    dsa_secret_key::dsa_secret_key(multiprecision_integer p, multiprecision_integer q, multiprecision_integer g, multiprecision_integer y, multiprecision_integer x) noexcept :
        dsa_public_key{ std::move(p), std::move(q), std::move(g), std::move(y) },
        _x{ std::move(x) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t dsa_secret_key::size() const noexcept
    {
        // we need the size from the parent and to encode the secret exponent
        return dsa_public_key::size() + _x.size();
    }

    /**
     *  Retrieve the secret exponent
     *
     *  @return The secret exponent x
     */
    const multiprecision_integer &dsa_secret_key::x() const noexcept
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
    void dsa_secret_key::encode(encoder &writer) const
    {
        // first encode the parent and then add the secret exponent
        dsa_public_key::encode(writer);
        _x.encode(writer);
    }

}
