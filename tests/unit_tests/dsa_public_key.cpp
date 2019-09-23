#include <gtest/gtest.h>        // for TEST
#include "../key_template.h"    // for key_test
#include "dsa_public_key.h"     // for dsa_public_key


TEST(dsa_public_key, test)
{
    using key_type = pgp::dsa_public_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::p>,
        tests::parameters::mpi<&key_type::q>,
        tests::parameters::mpi<&key_type::g>,
        tests::parameters::mpi<&key_type::y>>();
}
