#include "elgamal_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data from
     */
    elgamal_public_key::elgamal_public_key(decoder &parser) :
        _p{ parser },
        _g{ parser },
        _y{ parser }
    {}

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
    const multiprecision_integer elgamal_public_key::p() const noexcept
    {
        // return the stored prime
        return _p;
    }

    /**
     *  Retrieve the group generator g
     *
     *  @return The group generator g
     */
    const multiprecision_integer elgamal_public_key::g() const noexcept
    {
        // return the stored generator
        return _g;
    }

    /**
     *  Retrieve the public key value
     *
     *  @return The public key value
     */
    const multiprecision_integer elgamal_public_key::y() const noexcept
    {
        // return the stored public key value
        return _y;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void elgamal_public_key::encode(encoder &writer) const
    {
        // encode all the components
        _p.encode(writer);
        _g.encode(writer);
        _y.encode(writer);
    }

}
