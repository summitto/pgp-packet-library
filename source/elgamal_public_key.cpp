#include "elgamal_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  p       The prime p
     *  @param  g       The group generator g
     *  @param  y       The public key value: g**x mod p
     */
    elgamal_public_key::elgamal_public_key(multiprecision_integer p, multiprecision_integer g, multiprecision_integer y) noexcept :
        _p{ std::move(p) },
        _g{ std::move(g) },
        _y{ std::move(y) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool elgamal_public_key::operator==(const elgamal_public_key &other) const noexcept
    {
        return p() == other.p() && g() == other.g() && y() == other.y();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool elgamal_public_key::operator!=(const elgamal_public_key &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t elgamal_public_key::size() const noexcept
    {
        // we need to store all the components
        return _p.size() + _g.size() + _y.size();
    }

    /**
     *  Retrieve the the prime
     *
     *  @return The prime p
     */
    const multiprecision_integer &elgamal_public_key::p() const noexcept
    {
        // return the stored prime
        return _p;
    }

    /**
     *  Retrieve the group generator g
     *
     *  @return The group generator g
     */
    const multiprecision_integer &elgamal_public_key::g() const noexcept
    {
        // return the stored generator
        return _g;
    }

    /**
     *  Retrieve the public key value
     *
     *  @return The public key value
     */
    const multiprecision_integer &elgamal_public_key::y() const noexcept
    {
        // return the stored public key value
        return _y;
    }

}
