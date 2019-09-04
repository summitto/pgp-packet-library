#include <gtest/gtest.h>
#include "decoder.h"
#include "expected_number.h"
#include "fixed_number.h"
#include "range_encoder.h"


TEST(expected_number, decode_encode)
{
    std::array<uint8_t, 8> data;

    pgp::range_encoder encoder{data};
    pgp::fixed_number<uint32_t>{42}.encode(encoder);
    pgp::fixed_number<uint32_t>{123}.encode(encoder);

    pgp::decoder decoder{data};

    pgp::expected_number<uint32_t, 42>{decoder};
    ASSERT_THROW((pgp::expected_number<uint32_t, 43>{decoder}), std::range_error);
}
