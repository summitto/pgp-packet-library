#include <array>
#include <vector>
#include <gtest/gtest.h>
#include "../../unknown_signature_subpacket.h"
#include "../../range_encoder.h"
#include "../../decoder.h"


TEST(unknown_signature_subpacket, properties)
{
    auto type_1 = pgp::signature_subpacket_type::features;

    std::array<uint8_t, 10> data{1, 5, 3, 3, 7, 5, 3, 4, 3, 4};

    pgp::decoder decoder{data};
    pgp::unknown_signature_subpacket p1{type_1, decoder};
    pgp::unknown_signature_subpacket p2{type_1, data};
    ASSERT_EQ(p1.data(), p2.data());

    // Two extra bytes: one for the variable_number, one for the type tag
    ASSERT_EQ(p1.size(), 2 + data.size());
    ASSERT_EQ(p1.type(), type_1);
}
