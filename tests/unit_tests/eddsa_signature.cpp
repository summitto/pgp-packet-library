#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <memory>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>
#include "../../eddsa_signature.h"
#include "../../range_encoder.h"
#include "../../decoder.h"


namespace {
    struct inputs {
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pubkey;
        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> seckey;
        std::array<uint8_t, 32> message;
        std::unique_ptr<pgp::eddsa_signature> sig;
    };

    inputs generate_inputs()
    {
        inputs inps;
        randombytes_buf(inps.pubkey.data(), inps.pubkey.size());
        randombytes_buf(inps.seckey.data(), inps.seckey.size());
        randombytes_buf(inps.message.data(), inps.message.size());
        crypto_sign_keypair(inps.pubkey.data(), inps.seckey.data());

        pgp::secret_key sk{
            1554106568,
            pgp::key_algorithm::eddsa,
            mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>(),
            std::make_tuple(pgp::curve_oid::ed25519(), pgp::multiprecision_integer(inps.pubkey)),
            std::make_tuple(pgp::multiprecision_integer(inps.seckey))
        };

        inps.sig = std::make_unique<pgp::eddsa_signature>(sk, inps.message);

        return inps;
    }
}

TEST(eddsa_signature, test)
{
    inputs inps{generate_inputs()};

    ASSERT_EQ(inps.sig->size(), inps.sig->r().size() + inps.sig->s().size());

    auto rdata = inps.sig->r().data(), sdata = inps.sig->s().data();

    ASSERT_LE(rdata.size(), 32);
    ASSERT_LE(sdata.size(), 32);

    std::array<uint8_t, 64> sigdata;
    std::fill(sigdata.begin(), sigdata.end(), 0);

    std::copy(rdata.begin(), rdata.end(), sigdata.begin() + 32 - rdata.size());
    std::copy(sdata.begin(), sdata.end(), sigdata.begin() + 64 - sdata.size());

    ASSERT_EQ(
        crypto_sign_verify_detached(
            sigdata.data(),
            inps.message.data(), inps.message.size(),
            inps.pubkey.data()),
        0);
}

TEST(eddsa_signature, constructor)
{
    inputs inps{generate_inputs()};

    pgp::eddsa_signature sig2{inps.sig->r(), inps.sig->s()};
    ASSERT_EQ(inps.sig->r().data(), sig2.r().data());
    ASSERT_EQ(inps.sig->s().data(), sig2.s().data());
}

TEST(eddsa_signature, encode_decode)
{
    inputs inps{generate_inputs()};

    std::vector<uint8_t> data(128);
    pgp::range_encoder encoder{data};

    inps.sig->encode(encoder);

    ASSERT_EQ(encoder.size(), inps.sig->size());

    data.resize(encoder.size());

    pgp::decoder decoder{data};
    pgp::eddsa_signature sig2{decoder};
    ASSERT_EQ(*inps.sig, sig2);
}

TEST(eddsa_signature, equality)
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
