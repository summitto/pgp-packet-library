#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <memory>
#include <sodium/crypto_sign.h>
#include "dsa_signature.h"
#include "range_encoder.h"
#include "decoder.h"
#include "../key_template.h"


TEST(dsa_signature, encode_decode)
{
    auto rval = tests::parameters::generate::mpi();
    auto sval = tests::parameters::generate::mpi();
    pgp::dsa_signature sig{rval, sval};

    ASSERT_EQ(sig.size(), rval.size() + sval.size());
    ASSERT_EQ(sig.r().data(), rval.data());
    ASSERT_EQ(sig.s().data(), sval.data());

    std::vector<uint8_t> data(2048);
    pgp::range_encoder encoder{data};
    sig.encode(encoder);

    ASSERT_EQ(encoder.size(), sig.size());

    pgp::decoder decoder{data};
    pgp::dsa_signature sig2{decoder};

    ASSERT_EQ(sig, sig2);
}

TEST(dsa_signature, equality)
{
    pgp::multiprecision_integer rval{std::array<uint8_t, 3>{1, 2, 3}};
    pgp::multiprecision_integer sval{std::array<uint8_t, 3>{4, 5, 6}};
    pgp::multiprecision_integer diff{std::array<uint8_t, 3>{7, 8, 9}};

    pgp::dsa_signature sig{rval, sval};
    ASSERT_EQ(sig, sig);

    pgp::dsa_signature sig2{diff, sval};
    ASSERT_NE(sig, sig2);

    pgp::dsa_signature sig3{rval, diff};
    ASSERT_NE(sig, sig3);
}
