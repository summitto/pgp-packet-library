#include "ecdsa_signature.h"
#include "null_hash.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <string>
#include <algorithm>

namespace pgp {

    ecdsa_signature::encoder_t::encoder_t(secret_key key) noexcept :
        key{key}
    {}

    std::tuple<multiprecision_integer, multiprecision_integer>
    ecdsa_signature::encoder_t::finalize()
    {
        // retrieve the key implementation
        auto &ecdsa_key = mpark::get<basic_secret_key<ecdsa_public_key, ecdsa_secret_key>>(key.key());

        // Crypto++ does not export this information as constexpr
        constexpr size_t signature_length = 64;

        // retrieve the key data
        auto secret_data = ecdsa_key.k().data();

        // ECDSA needs randomness for signatures
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::Integer k1_exponent;
        k1_exponent.Decode(secret_data.data(), secret_data.size());

        CryptoPP::ECDSA<CryptoPP::ECP, NullHash<32>>::PrivateKey k1;
        k1.Initialize(CryptoPP::ASN1::secp256r1(), k1_exponent);

        // the buffer for the signed message and the concatenated key
        std::array<uint8_t, signature_length> signed_message;

        // construct the signer
        CryptoPP::ECDSA<CryptoPP::ECP, NullHash<32>>::Signer signer{k1};

        if (signer.MaxSignatureLength() != signature_length) {
            throw std::logic_error("Unexpected Crypto++ ECDSA maximum signature length");
        }

        // get the digest to sign
        auto digest_data = digest();

        // now sign the message
        size_t actual_length = signer.SignMessage(prng, digest_data.data(), digest_data.size(), signed_message.data());

        if (actual_length != signature_length) {
            throw std::logic_error("Unexpected Crypto++ ECDSA actual signature length");
        }

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
    ecdsa_signature::ecdsa_signature(decoder &parser) :
        _r{ parser },
        _s{ parser }
    {}


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
