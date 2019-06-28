#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <memory>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>
#include "eddsa_signature.h"
#include "range_encoder.h"
#include "hash_encoder.h"
#include "generate.h"
#include "decoder.h"


namespace {
    constexpr const std::array<uint8_t, 1> public_key_tag{0x40};
    constexpr const size_t public_key_size = public_key_tag.size() + crypto_sign_PUBLICKEYBYTES;
    constexpr const size_t secret_key_size = crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES;

    struct inputs {
        std::array<uint8_t, public_key_size> pubkey;
        std::array<uint8_t, secret_key_size> seckey;
        std::array<uint8_t, 32> message;
        std::unique_ptr<pgp::eddsa_signature> sig;
    };

    std::array<uint8_t, 32> sha256_hash(pgp::span<const uint8_t> data)
    {
        pgp::sha256_encoder encoder;
        encoder.insert_blob(data);
        return encoder.digest();
    }

    inputs generate_inputs()
    {
        inputs inps;

        auto key_res = tests::generate::eddsa::key();
        const pgp::secret_key &sk = std::get<0>(key_res);
        inps.pubkey = std::get<1>(key_res);
        inps.seckey = std::get<2>(key_res);

        std::array<uint8_t, 32> message;
        randombytes_buf(message.data(), message.size());
        inps.message = sha256_hash(pgp::span<const uint8_t>{message});

        pgp::eddsa_signature::encoder_t sig_encoder{sk};
        sig_encoder.insert_blob(pgp::span<const uint8_t>{message});
        inps.sig = std::make_unique<pgp::eddsa_signature>(
            util::make_from_tuple<pgp::eddsa_signature>(sig_encoder.finalize())
        );

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
            inps.pubkey.data() + public_key_tag.size()),
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
