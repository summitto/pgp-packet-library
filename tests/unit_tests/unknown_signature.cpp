#include <gtest/gtest.h>
#include <vector>
#include "unknown_signature.h"
#include "range_encoder.h"
#include "decoder.h"


TEST(unknown_signature, test)
{
    pgp::unknown_signature sig;
    ASSERT_THROW(sig.size(), std::runtime_error);

    std::vector<uint8_t> v;
    pgp::range_encoder encoder{v};
    ASSERT_THROW(sig.encode(encoder), std::runtime_error);

    pgp::decoder decoder{v};
    pgp::unknown_signature sig2{decoder};
}

TEST(unknown_signature, equality)
{
    ASSERT_EQ(pgp::unknown_signature{}, pgp::unknown_signature{});
    ASSERT_FALSE(pgp::unknown_signature{} != pgp::unknown_signature{});
}
