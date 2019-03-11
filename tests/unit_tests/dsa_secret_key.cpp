#include <gtest/gtest.h>
#include "../key_template.h"
#include "../../dsa_secret_key.h"


TEST(dsa_secret_key, test)
{
    using key_type = pgp::dsa_secret_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::x>>();
}
