#include <gtest/gtest.h>
#include "../key_template.h"
#include "rsa_public_key.h"


TEST(rsa_public_key, test)
{
    using key_type = pgp::rsa_public_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::n>,
        tests::parameters::mpi<&key_type::e>>();
}
