#include "eddsa_signature.h"
#include <sodium/crypto_sign.h>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    eddsa_signature::eddsa_signature(decoder &parser) :
        _r{ parser },
        _s{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  key     The key to use for signing
     *  @param  digest  The hash that needs to be signed
     */
    eddsa_signature::eddsa_signature(const secret_key &key, std::array<uint8_t, 32> digest)
    {
        // retrieve the key implementation
        auto &eddsa_key = mpark::get<basic_secret_key<eddsa_public_key, eddsa_secret_key>>(key.key());

        // the buffer for the signed message and the concatenated key
        std::array<uint8_t, crypto_sign_BYTES>  signed_message;
        std::array<uint8_t, 64>                 key_data;

        // retrieve the key data - ignore the silly leading byte from the public key
        auto public_data = eddsa_key.Q().data().subspan<1>();
        auto secret_data = eddsa_key.k().data();

        // copy the public key and then the private key
        auto iter = std::copy(secret_data.begin(), secret_data.end(), key_data.begin());
        std::copy(public_data.begin(), public_data.end(), iter);

        // now sign the message
        crypto_sign_detached(signed_message.data(), nullptr, digest.data(), digest.size(), key_data.data());

        // split up the data and assign it
        _r = gsl::span{ signed_message.data(),      32 };
        _s = gsl::span{ signed_message.data() + 32, 32 };
    }

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
