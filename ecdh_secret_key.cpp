#include "ecdh_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    ecdh_secret_key::ecdh_secret_key(decoder &parser) :
        ecdh_public_key{ parser },
        _k{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  curve           The curve object identifier
     *  @param  Q               The public curve point Q
     *  @param  hash_function   The used KDF hash function
     *  @param  algorithm       The symmetric alforithm for wrapping the symmetric key
     *  @param  k               The secret scalar for the public point
     */
    ecdh_secret_key::ecdh_secret_key(curve_oid curve, multiprecision_integer Q, uint8_t hash_function, uint8_t algorithm, multiprecision_integer k) noexcept :
        ecdh_public_key{ std::move(curve), std::move(Q), hash_function, algorithm },
        _k{ std::move(k) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t ecdh_secret_key::size() const noexcept
    {
        // we need the size of the parent plus the size for the secret key
        return ecdh_public_key::size() + _k.size();
    }

    /**
     *  Retrieve the secret scalar
     *
     *  @return The secret scalar for the public point
     */
    const multiprecision_integer &ecdh_secret_key::k() const noexcept
    {
        // return the stored scalar
        return _k;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void ecdh_secret_key::encode(encoder &writer) const
    {
        // first encode the parent, then add the secret key k
        ecdh_public_key::encode(writer);
        _k.encode(writer);
    }

}
