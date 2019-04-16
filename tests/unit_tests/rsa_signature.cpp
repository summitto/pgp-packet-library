#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <memory>
#include <sodium/crypto_sign.h>
#include "../../rsa_signature.h"
#include "../../range_encoder.h"
#include "../../decoder.h"
#include "../key_template.h"


TEST(rsa_signature, encode_decode)
{
    auto sval = tests::parameters::generate::mpi();
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
    pgp::rsa_signature sig{pgp::multiprecision_integer{gsl::span<const uint8_t>{{1, 2, 3}}}};
    pgp::rsa_signature sig2{pgp::multiprecision_integer{gsl::span<const uint8_t>{{4, 5, 6}}}};

    ASSERT_EQ(sig, sig);
    ASSERT_NE(sig, sig2);
}
