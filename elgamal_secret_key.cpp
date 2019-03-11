#include "elgamal_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data from
     */
    elgamal_secret_key::elgamal_secret_key(decoder &parser) :
        _x{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  x       The secret exponent x
     */
    elgamal_secret_key::elgamal_secret_key(multiprecision_integer x) noexcept :
        _x{ std::move(x) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool elgamal_secret_key::operator==(const elgamal_secret_key &other) const noexcept
    {
        return x() == other.x();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool elgamal_secret_key::operator!=(const elgamal_secret_key &other) const noexcept
    { return !(*this == other); }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t elgamal_secret_key::size() const noexcept
    {
        // we need the size for our secret exponent
        return _x.size();
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

}
