#include "rsa_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    rsa_public_key::rsa_public_key(decoder &parser) :
        _n{ parser },
        _e{ parser }
    {}

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

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void rsa_public_key::encode(encoder &writer) const
    {
        // encode the modulus and the exponent
        _n.encode(writer);
        _e.encode(writer);
    }

}