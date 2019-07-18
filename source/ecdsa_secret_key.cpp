#include "ecdsa_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  k       The secret scalar for the public point
     */
    ecdsa_secret_key::ecdsa_secret_key(multiprecision_integer k) noexcept :
        _k{ std::move(k) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool ecdsa_secret_key::operator==(const ecdsa_secret_key &other) const noexcept
    {
        return k() == other.k();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool ecdsa_secret_key::operator!=(const ecdsa_secret_key &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t ecdsa_secret_key::size() const noexcept
    {
        // we need to store the secret scalar
        return _k.size();
    }

    /**
     *  Retrieve the secret scalar
     *
     *  @return The secret scalar for the public point
     */
    const multiprecision_integer &ecdsa_secret_key::k() const noexcept
    {
        // return the stored scalar
        return _k;
    }

}
