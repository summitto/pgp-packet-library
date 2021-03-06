#include <gtest/gtest.h>
#include "../key_template.h"
#include "dsa_public_key.h"


TEST(dsa_public_key, test)
{
    using key_type = pgp::dsa_public_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::p>,
        tests::parameters::mpi<&key_type::q>,
        tests::parameters::mpi<&key_type::g>,
        tests::parameters::mpi<&key_type::y>>();
}
