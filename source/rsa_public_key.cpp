#include "rsa_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  n   The public modulus n
     *  @param  e   The encryption exponent e
     */
    rsa_public_key::rsa_public_key(multiprecision_integer n, multiprecision_integer e) noexcept :
        _n{ std::move(n) },
        _e{ std::move(e) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_public_key::operator==(const rsa_public_key &other) const noexcept
    {
        return n() == other.n() && e() == other.e();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_public_key::operator!=(const rsa_public_key &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t rsa_public_key::size() const noexcept
    {
        // we need to store the n and e components
        return _n.size() + _e.size();
    }

    /**
     *  Retrieve the public modulus n
     *
     *  @return The modulus n for the key
     */
    const multiprecision_integer &rsa_public_key::n() const noexcept
    {
        // return the stored modulus
        return _n;
    }

    /**
     *  Retrieve the encryption exponent e
     *
     *  @return The encryption exponent e
     */
    const multiprecision_integer &rsa_public_key::e() const noexcept
    {
        // return the stored exponent
        return _e;
    }

}
