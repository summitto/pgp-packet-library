#include "rsa_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  d   The secret exponent d
     *  @param  p   The secret prime value p
     *  @param  q   The secret prime value q
     *  @param  u   The multiplicative inverse p mod q
     */
    rsa_secret_key::rsa_secret_key(multiprecision_integer d, multiprecision_integer p, multiprecision_integer q, multiprecision_integer u) noexcept :
        _d{ std::move(d) },
        _p{ std::move(p) },
        _q{ std::move(q) },
        _u{ std::move(u) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_secret_key::operator==(const rsa_secret_key &other) const noexcept
    {
        return d() == other.d() && p() == other.p() && q() == other.q() && u() == other.u();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_secret_key::operator!=(const rsa_secret_key &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t rsa_secret_key::size() const noexcept
    {
        // we need the size of secret components
        return _d.size() + _p.size() + _q.size() + _u.size();
    }

    /**
     *  Retrieve the secret exponent d
     *
     *  @return The secret exponent
     */
    const multiprecision_integer &rsa_secret_key::d() const noexcept
    {
        // return the storet exponent
        return _d;
    }

    /**
     *  Retrieve the secret prime value p
     *
     *  @return The secret prime value p
     */
    const multiprecision_integer &rsa_secret_key::p() const noexcept
    {
        // return the stored prime
        return _p;
    }

    /**
     *  Retrieve the secret prime value q
     *
     *  @return The secret prime value q
     */
    const multiprecision_integer &rsa_secret_key::q() const noexcept
    {
        // return the stored prime
        return _q;
    }

    /**
     *  Retrieve the u value
     *
     *  @return The multiplicative inverse of p mod q
     */
    const multiprecision_integer &rsa_secret_key::u() const noexcept
    {
        // return the stored multiplicative
        return _u;
    }

}
