#include <gtest/gtest.h>
#include "../key_template.h"
#include "elgamal_secret_key.h"


TEST(elgamal_secret_key, test)
{
    using key_type = pgp::elgamal_secret_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::x>>();
}
