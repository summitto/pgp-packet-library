#include "ecdh_secret_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    ecdh_secret_key::ecdh_secret_key(decoder &parser) :
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
    ecdh_secret_key::ecdh_secret_key(multiprecision_integer k) noexcept :
        _k{ std::move(k) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t ecdh_secret_key::size() const noexcept
    {
        // we need to store the secret scalar
        return _k.size();
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
        // encode the secret scalar
        _k.encode(writer);
    }

}
