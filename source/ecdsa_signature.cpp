#include "ecdsa_signature.h"
#include <string>
#include <algorithm>

namespace pgp {

    /**
     *  Constructor
     *
     *  @param  r       The ECDSA r value
     *  @param  s       The ECDSA s value
     */
    ecdsa_signature::ecdsa_signature(multiprecision_integer r, multiprecision_integer s) noexcept :
        _r{ std::move(r) },
        _s{ std::move(s) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool ecdsa_signature::operator==(const ecdsa_signature &other) const noexcept
    {
        return r() == other.r() && s() == other.s();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool ecdsa_signature::operator!=(const ecdsa_signature &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t ecdsa_signature::size() const noexcept
    {
        // we need space to store both values
        return _r.size() + _s.size();
    }

    /**
     *  Retrieve the ECDSA r value
     *
     *  @return The r value
     */
    const multiprecision_integer &ecdsa_signature::r() const noexcept
    {
        // return the r value
        return _r;
    }

    /**
     *  Retrieve the ECDSA s value
     *
     *  @return The s value
     */
    const multiprecision_integer &ecdsa_signature::s() const noexcept
    {
        // return the s value
        return _s;
    }

}
