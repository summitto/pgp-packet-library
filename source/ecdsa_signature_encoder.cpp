#include "ecdsa_signature_encoder.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include "null_hash.h"
#include <stdexcept>


namespace pgp {

    /**
     *  Make the signature
     *
     *  @return Tuple of the r and s parameters for the ECDSA signature
     */
    std::tuple<multiprecision_integer, multiprecision_integer>
    ecdsa_signature_encoder::finalize()
    {
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

}
