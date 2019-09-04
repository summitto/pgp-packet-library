#include "eddsa_signature.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  r       The EdDSA r value
     *  @param  s       The EdDSA s value
     */
    eddsa_signature::eddsa_signature(multiprecision_integer r, multiprecision_integer s) noexcept :
        _r{ std::move(r) },
        _s{ std::move(s) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool eddsa_signature::operator==(const eddsa_signature &other) const noexcept
    {
        return r() == other.r() && s() == other.s();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool eddsa_signature::operator!=(const eddsa_signature &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t eddsa_signature::size() const noexcept
    {
        // we need space to store both values
        return _r.size() + _s.size();
    }

    /**
     *  Retrieve the EdDSA r value
     *
     *  @return The r value
     */
    const multiprecision_integer &eddsa_signature::r() const noexcept
    {
        // return the r value
        return _r;
    }

    /**
     *  Retrieve the EdDSA s value
     *
     *  @return The s value
     */
    const multiprecision_integer &eddsa_signature::s() const noexcept
    {
        // return the s value
        return _s;
    }

}
