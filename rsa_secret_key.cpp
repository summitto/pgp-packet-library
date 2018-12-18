#include "rsa_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    rsa_secret_key::rsa_secret_key(decoder &parser) :
        rsa_public_key{ parser },
        _d{ parser },
        _p{ parser },
        _q{ parser },
        _u{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  n   The public modulus n
     *  @param  e   The encryption exponent e
     *  @param  d   The secret exponent d
     *  @param  p   The secret prime value p
     *  @param  q   The secret prime value q
     *  @param  u   The multiplicative inverse p mod q
     */
    rsa_secret_key::rsa_secret_key(multiprecision_integer n, multiprecision_integer e, multiprecision_integer d, multiprecision_integer p, multiprecision_integer q, multiprecision_integer u) noexcept :
        rsa_public_key{ std::move(n), std::move(e) },
        _d{ std::move(d) },
        _p{ std::move(p) },
        _q{ std::move(q) },
        _u{ std::move(u) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t rsa_secret_key::size() const noexcept
    {
        // we need the size of the parent plus the size of the secret components
        return rsa_public_key::size() + _d.size() + _p.size() + _q.size() + _u.size();
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

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void rsa_secret_key::encode(encoder &writer) const
    {
        // encode parent first and then add all the secret fields
        rsa_public_key::encode(writer);
        _d.encode(writer);
        _p.encode(writer);
        _q.encode(writer);
        _u.encode(writer);
    }

}
