#include <limits>
#include <gtest/gtest.h>
#include "variable_number.h"
#include "range_encoder.h"
#include "decoder.h"


TEST(variable_number, faithful_encoding)
{
    for (uint32_t n = 0; n < 10000; n++) {
        pgp::variable_number varnum{n};

        std::vector<uint8_t> data(6);
        pgp::range_encoder encoder{data};
        varnum.encode(encoder);

        ASSERT_EQ(encoder.size(), varnum.size());
        data.resize(encoder.size());

        pgp::decoder decoder{data};
        pgp::variable_number result{decoder};
        ASSERT_EQ(n, result);
    }
}

TEST(variable_number, assignment)
{
	for (uint32_t n = 0; n < 100; n++) {
		pgp::variable_number varnum;
		// Test the assignment operator
		varnum = n;
		ASSERT_EQ(varnum, n);
	}
}
