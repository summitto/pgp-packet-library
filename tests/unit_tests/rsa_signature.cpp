#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <memory>
#include <sodium/randombytes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include "../../rsa_signature.h"
#include "../../range_encoder.h"
#include "../../decoder.h"


namespace {
    struct inputs {
        CryptoPP::RSA::PrivateKey private_key;
        pgp::rsa_public_key pubkey;
        pgp::rsa_secret_key seckey;

        std::array<uint8_t, 32> message;
        std::unique_ptr<pgp::rsa_signature> sig;

        inputs(CryptoPP::RSA::PrivateKey &&private_key):
            private_key{private_key},
            pubkey{
                private_key.GetModulus(),
                private_key.GetPublicExponent()
            },
            seckey{
                private_key.GetPrivateExponent(),
                private_key.GetPrime1(),
                private_key.GetPrime2(),
                private_key.GetMultiplicativeInverseOfPrime2ModPrime1()
            }
        {}
    };

    inputs generate_inputs(size_t modulus_size)
    {
        CryptoPP::AutoSeededRandomPool rng;

        // generate a private key, and construct the inputs struct with it
        CryptoPP::RSA::PrivateKey private_key;
        private_key.GenerateRandomWithKeySize(rng, modulus_size);
        inputs inps{std::move(private_key)};

        // generate a random message
        randombytes_buf(inps.message.data(), inps.message.size());

        // construct the secret key with the derived key parameters
        pgp::secret_key sk{
            1554106568,
            pgp::key_algorithm::rsa_encrypt_or_sign,
            mpark::in_place_type_t<pgp::secret_key::rsa_key_t>(),
            std::make_tuple(inps.pubkey),
            std::make_tuple(inps.seckey)
        };

        // and make the signature
        pgp::rsa_signature::encoder_t sig_encoder{sk};
        sig_encoder.insert_blob(gsl::span<const uint8_t>{inps.message});
        inps.sig = std::make_unique<pgp::rsa_signature>(
            util::make_from_tuple<pgp::rsa_signature>(sig_encoder.finalize())
        );

        return inps;
    }
}

TEST(rsa_signature, test)
{
    inputs inps{generate_inputs(2048)};

    CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier{inps.private_key};

    ASSERT_TRUE(verifier.VerifyMessage(
        inps.message.data(), inps.message.size(),
        inps.sig->s().data().data(), inps.sig->s().data().size()
    ));
}

TEST(rsa_signature, encode_decode)
{
    inputs inps{generate_inputs(2048)};
    pgp::multiprecision_integer sval = inps.sig->s();
    pgp::rsa_signature sig{sval};

    ASSERT_EQ(sig.size(), sval.size());
    ASSERT_EQ(sig.s().data(), sval.data());

    std::vector<uint8_t> data(2048);
    pgp::range_encoder encoder{data};
    sig.encode(encoder);

    ASSERT_EQ(encoder.size(), sig.size());

    pgp::decoder decoder{data};
    pgp::rsa_signature sig2{decoder};

    ASSERT_EQ(sig, sig2);
}

TEST(rsa_signature, equality)
{
    pgp::rsa_signature sig{pgp::multiprecision_integer{std::array<uint8_t, 3>{1, 2, 3}}};
    pgp::rsa_signature sig2{pgp::multiprecision_integer{std::array<uint8_t, 3>{4, 5, 6}}};

    ASSERT_EQ(sig, sig);
    ASSERT_NE(sig, sig2);
}
