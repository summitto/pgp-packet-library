#include "dsa_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    dsa_secret_key::dsa_secret_key(decoder &parser) :
        _x{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  x   The secret exponent
     */
    dsa_secret_key::dsa_secret_key(multiprecision_integer x) noexcept :
        _x{ std::move(x) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool dsa_secret_key::operator==(const dsa_secret_key &other) const noexcept
    {
        return x() == other.x();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool dsa_secret_key::operator!=(const dsa_secret_key &other) const noexcept
    { return !(*this == other); }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t dsa_secret_key::size() const noexcept
    {
        // we need to encode the secret exponent
        return _x.size();
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

}
