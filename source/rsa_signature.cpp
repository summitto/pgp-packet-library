#include <cryptopp/osrng.h>
#include "rsa_signature.h"
#include <cryptopp/rsa.h>
#include <stdexcept>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  s       The signature value (m**d mod n)
     */
    rsa_signature::rsa_signature(multiprecision_integer s) noexcept :
        _s{ std::move(s) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_signature::operator==(const rsa_signature &other) const noexcept
    {
        return s() == other.s();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_signature::operator!=(const rsa_signature &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t rsa_signature::size() const noexcept
    {
        // we only need space for encoding the signature
        return _s.size();
    }

    /**
     *  Retrieve the signature value
     *
     *  @return The signature value (m**d mod n)
     */
    const multiprecision_integer &rsa_signature::s() const noexcept
    {
        // return the signature
        return _s;
    }

}
