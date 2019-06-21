#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <memory>
#include <sodium/randombytes.h>
#include <sodium/crypto_sign.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include "ecdsa_signature.h"
#include "range_encoder.h"
#include "decoder.h"
#include "null_hash.h"


namespace {
    constexpr const size_t PUBLICKEYBYTES = 64;
    constexpr const size_t SECRETKEYBYTES = 32;

    using CryptoPP_public_key = CryptoPP::ECDSA<CryptoPP::ECP, pgp::NullHash<32>>::PublicKey;

    void generate_ecdsa_keypair(
        std::array<uint8_t, PUBLICKEYBYTES> &pubkey,
        std::array<uint8_t, SECRETKEYBYTES> &seckey,
        CryptoPP_public_key &cryptopp_pubkey
    )
    {
        // Create a random number generator to generate the key elements
        CryptoPP::AutoSeededRandomPool prng;

        // Generate the secret key
        CryptoPP::ECDSA<CryptoPP::ECP, pgp::NullHash<32>>::PrivateKey secret_key;
        secret_key.Initialize(prng, CryptoPP::ASN1::secp256r1());

        // Encode the secret key
        const CryptoPP::Integer &secret_key_exponent = secret_key.GetPrivateExponent();
        secret_key_exponent.Encode(seckey.data(), seckey.size());

        // Generate the public key
        secret_key.MakePublicKey(cryptopp_pubkey);

        // Get the public key point
        const CryptoPP::ECP::Point &public_key_q = cryptopp_pubkey.GetPublicElement();

        // Encode the public key
        constexpr const size_t integer_size = 32;
        static_assert(2 * integer_size == PUBLICKEYBYTES);
        public_key_q.x.Encode(pubkey.data(), integer_size);
        public_key_q.y.Encode(pubkey.data() + integer_size, integer_size);
    }

    struct inputs {
        std::array<uint8_t, PUBLICKEYBYTES> pubkey;
        std::array<uint8_t, SECRETKEYBYTES> seckey;
        CryptoPP_public_key cryptopp_pubkey;
        std::array<uint8_t, 20> message;
        std::unique_ptr<pgp::ecdsa_signature> sig;
    };

    inputs generate_inputs()
    {
        inputs inps;
        randombytes_buf(inps.message.data(), inps.message.size());
        generate_ecdsa_keypair(inps.pubkey, inps.seckey, inps.cryptopp_pubkey);

        pgp::secret_key sk{
            1554106568,
            pgp::key_algorithm::ecdsa,
            pgp::in_place_type_t<pgp::secret_key::ecdsa_key_t>(),
            std::make_tuple(pgp::curve_oid::ed25519(), pgp::multiprecision_integer(inps.pubkey)),
            std::make_tuple(pgp::multiprecision_integer(inps.seckey))
        };

        pgp::ecdsa_signature::encoder_t sig_encoder{sk};
        sig_encoder.insert_blob(pgp::span<const uint8_t>{inps.message});
        inps.sig = std::make_unique<pgp::ecdsa_signature>(
            util::make_from_tuple<pgp::ecdsa_signature>(sig_encoder.finalize())
        );

        return inps;
    }
}

TEST(ecdsa_signature, test)
{
    // generate the inputs
    inputs inps{generate_inputs()};

    // test size
    ASSERT_EQ(inps.sig->size(), inps.sig->r().size() + inps.sig->s().size());

    // get the signature integers
    auto rdata = inps.sig->r().data(), sdata = inps.sig->s().data();

    ASSERT_LE(rdata.size(), 32);
    ASSERT_LE(sdata.size(), 32);

    // construct the signature data array
    std::array<uint8_t, 64> sigdata;
    std::fill(sigdata.begin(), sigdata.end(), 0);

    std::copy(rdata.begin(), rdata.end(), sigdata.begin() + 32 - rdata.size());
    std::copy(sdata.begin(), sdata.end(), sigdata.begin() + 64 - sdata.size());

    // check the signature

    // Usually in this library, we pass pgp::NullHash as the hasher to EC
    // templates, because we do the hashing ourselves. Here, however, we have
    // contrived to create a good signature, so the complete, normal
    // verification, including hash, should just work.
    ASSERT_TRUE(
        (CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier{inps.cryptopp_pubkey}.VerifyMessage(
            inps.message.data(), inps.message.size(),
            sigdata.data(), sigdata.size()
        ))
    );
}

TEST(ecdsa_signature, constructor)
{
    inputs inps{generate_inputs()};

    pgp::ecdsa_signature sig2{inps.sig->r(), inps.sig->s()};
    ASSERT_EQ(inps.sig->r().data(), sig2.r().data());
    ASSERT_EQ(inps.sig->s().data(), sig2.s().data());
}

TEST(ecdsa_signature, encode_decode)
{
    inputs inps{generate_inputs()};

    std::vector<uint8_t> data(128);
    pgp::range_encoder encoder{data};

    inps.sig->encode(encoder);

    ASSERT_EQ(encoder.size(), inps.sig->size());

    data.resize(encoder.size());

    pgp::decoder decoder{data};
    pgp::ecdsa_signature sig2{decoder};
    ASSERT_EQ(*inps.sig, sig2);
}

TEST(ecdsa_signature, equality)
{
    inputs inps{generate_inputs()};

    ASSERT_EQ(*inps.sig, *inps.sig);

    while (true) {
        inputs inps2{generate_inputs()};
        if (inps.pubkey != inps2.pubkey) {
            ASSERT_NE(*inps.sig, *inps2.sig);
            break;
        }
    }

    while (true) {
        inputs inps2{generate_inputs()};
        if (inps.seckey != inps2.seckey) {
            ASSERT_NE(*inps.sig, *inps2.sig);
            break;
        }
    }

    while (true) {
        inputs inps2{generate_inputs()};
        if (inps.message != inps2.message) {
            ASSERT_NE(*inps.sig, *inps2.sig);
            break;
        }
    }
}
