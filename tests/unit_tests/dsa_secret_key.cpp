#include <gtest/gtest.h>        // for TEST
#include "../key_template.h"    // for key_test
#include "dsa_secret_key.h"     // for dsa_secret_key


TEST(dsa_secret_key, test)
{
    using key_type = pgp::dsa_secret_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::x>>();
}
