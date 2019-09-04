#include "ecdh_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  curve           The curve object identifier
     *  @param  Q               The public curve point Q
     *  @param  hash_function   The used KDF hash function
     *  @param  algorithm       The symmetric alforithm for wrapping the symmetric key
     */
    ecdh_public_key::ecdh_public_key(curve_oid curve, multiprecision_integer Q, hash_algorithm hash_function, symmetric_key_algorithm algorithm) noexcept :
        _curve{ std::move(curve) },
        _Q{ std::move(Q) },
        _hash_function{ hash_function },
        _algorithm{ algorithm }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool ecdh_public_key::operator==(const ecdh_public_key &other) const noexcept
    {
        return curve() == other.curve() &&
                Q() == other.Q() &&
                hash_function() == other.hash_function() &&
                algorithm() == other.algorithm();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool ecdh_public_key::operator!=(const ecdh_public_key &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t ecdh_public_key::size() const noexcept
    {
        // add the size of all the components
        return _curve.size() + _Q.size() + _kdf_size.size() + _reserved.size() + sizeof _hash_function + sizeof _algorithm;
    }

    /**
     *  Retrieve the curve object identifier
     *
     *  @return The curve object identifier
     */
    const curve_oid &ecdh_public_key::curve() const noexcept
    {
        // return the stored curve id
        return _curve;
    }

    /**
     *  Retrieve the public curve point Q
     *
     *  @return The public curve point Q, in compressed format
     */
    const multiprecision_integer &ecdh_public_key::Q() const noexcept
    {
        // return the public key point
        return _Q;
    }

    /**
     *  Retrieve the KDF hash function
     *
     *  @return The KDF hash function
     */
    hash_algorithm ecdh_public_key::hash_function() const noexcept
    {
        // return the stored hash function
        return _hash_function;
    }

    /**
     *  Retrieve the symmetric algorithm
     *
     *  @return The symmetrict algorithm for wrapping the symmetric key
     */
    symmetric_key_algorithm ecdh_public_key::algorithm() const noexcept
    {
        // return the stored algorithm
        return _algorithm;
    }

}
