#include "ecdsa_signature.h"
#include "null_hash.h"
#include <sodium/crypto_sign.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <string>
#include <algorithm>

namespace pgp {

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
     *  @param  key     The key to use for signing
     *  @param  digest  The hash that needs to be signed
     */
    ecdsa_signature::ecdsa_signature(const secret_key &key, std::array<uint8_t, 32> digest)
    {
        // retrieve the key implementation
        auto &ecdsa_key = mpark::get<basic_secret_key<ecdsa_public_key, ecdsa_secret_key>>(key.key());

        // the buffer for the signed message and the concatenated key
        std::array<uint8_t, crypto_sign_BYTES>  signed_message;

        // retrieve the key data - ignore the silly leading byte from the public key
        auto public_data = ecdsa_key.Q().data().subspan<1>();
        auto secret_data = ecdsa_key.k().data();

        //ECDSA needs randomness for signatures
        CryptoPP::AutoSeededRandomPool prng;

        CryptoPP::ECDSA<CryptoPP::ECP, NullHash<32>>::PrivateKey k1;
        CryptoPP::Integer k1_exponent;

        k1_exponent.Decode(secret_data.data(), secret_data.size());
        k1.Initialize(CryptoPP::ASN1::secp256r1(), k1_exponent);

        CryptoPP::ECDSA<CryptoPP::ECP, NullHash<32>>::Signer signer(k1);
        // now sign the message
        signer.SignMessage( prng, digest.data(), digest.size(), signed_message.data() );

        // split up the data and assign it
        _r = gsl::span{ signed_message.data(),      32 };
        _s = gsl::span{ signed_message.data() + 32, 32 };
    }

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
