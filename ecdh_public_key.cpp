#include "ecdh_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    ecdh_public_key::ecdh_public_key(decoder &parser) :
        _curve{ parser },
        _Q{ parser },
        _kdf_size{ parser },
        _reserved{ parser },
        _hash_function{ parser },
        _algorithm{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  curve           The curve object identifier
     *  @param  Q               The public curve point Q
     *  @param  hash_function   The used KDF hash function
     *  @param  algorithm       The symmetric alforithm for wrapping the symmetric key
     */
    ecdh_public_key::ecdh_public_key(curve_oid curve, multiprecision_integer Q, uint8_t hash_function, uint8_t algorithm) noexcept :
        _curve{ std::move(curve) },
        _Q{ std::move(Q) },
        _hash_function{ hash_function },
        _algorithm{ algorithm }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t ecdh_public_key::size() const noexcept
    {
        // add the size of all the components
        return _curve.size() + _Q.size() + _kdf_size.size() + _reserved.size() + _hash_function.size() + _algorithm.size();
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
    uint8_t ecdh_public_key::hash_function() const noexcept
    {
        // return the stored hash function
        return _hash_function;
    }

    /**
     *  Retrieve the symmetric algorithm
     *
     *  @return The symmetrict algorithm for wrapping the symmetric key
     */
    uint8_t ecdh_public_key::algorithm() const noexcept
    {
        // return the stored algorithm
        return _algorithm;
    }

}
