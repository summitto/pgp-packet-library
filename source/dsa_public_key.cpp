#include "dsa_public_key.h"


namespace pgp {

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
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool dsa_public_key::operator==(const dsa_public_key &other) const noexcept
    {
        return p() == other.p() && q() == other.q() && g() == other.g() && y() == other.y();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool dsa_public_key::operator!=(const dsa_public_key &other) const noexcept
    {
        return !operator==(other);
    }

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

}
