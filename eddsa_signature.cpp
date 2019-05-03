#include "eddsa_signature.h"
#include <sodium/crypto_sign.h>


namespace pgp {

    eddsa_signature::encoder_t::encoder_t(secret_key key) noexcept :
        key{key}
    {}

    std::tuple<multiprecision_integer, multiprecision_integer>
    eddsa_signature::encoder_t::finalize() noexcept
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

        // get the digest to sign
        auto digest_data = digest();

        // now sign the message
        crypto_sign_detached(signed_message.data(), nullptr, digest_data.data(), digest_data.size(), key_data.data());

        // split up the data and return it
        return std::make_tuple(
            multiprecision_integer{gsl::span{ signed_message.data(),      32 }},
            multiprecision_integer{gsl::span{ signed_message.data() + 32, 32 }}
        );
    }

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
