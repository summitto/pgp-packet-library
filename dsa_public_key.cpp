#include "dsa_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    dsa_public_key::dsa_public_key(decoder &parser) :
        _p{ parser },
        _q{ parser },
        _g{ parser },
        _y{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  p   The prime p
     *  @param  q   The group order q
     *  @param  g   The generator g
     *  @param  y   The public key value
     */
    dsa_public_key::dsa_public_key(multiprecision_integer p, multiprecision_integer q, multiprecision_integer g, multiprecision_integer y) noexcept :
        _p{ std::move(p) },
        _q{ std::move(q) },
        _g{ std::move(g) },
        _y{ std::move(y) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t dsa_public_key::size() const noexcept
    {
        // we need to store all the components
        return _p.size() + _q.size() + _g.size() + _y.size();
    }

    /**
     *  Retrieve the prime p
     *
     *  @return The prime number p
     */
    const multiprecision_integer &dsa_public_key::p() const noexcept
    {
        // return the stored prime
        return _p;
    }

    /**
     *  Retrieve the group order q
     *
     *  @return The group number q
     */
    const multiprecision_integer &dsa_public_key::q() const noexcept
    {
        // return the stored group order
        return _q;
    }

    /**
     *  Retrieve the generator g
     *
     *  @return The generator g
     */
    const multiprecision_integer &dsa_public_key::g() const noexcept
    {
        // return the stored generator
        return _g;
    }

    /**
     *  Retrieve the public key value
     *
     *  @return The public key value: g**x mod p
     */
    const multiprecision_integer &dsa_public_key::y() const noexcept
    {
        // return the stored public key
        return _y;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void dsa_public_key::encode(encoder &writer) const
    {
        // encode all the integers
        _p.encode(writer);
        _q.encode(writer);
        _g.encode(writer);
        _y.encode(writer);
    }

}
