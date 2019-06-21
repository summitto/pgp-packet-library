#include <gtest/gtest.h>
#include "../key_template.h"
#include "ecdh_secret_key.h"


TEST(ecdh_secret_key, test)
{
    using key_type = pgp::ecdh_secret_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::k>>();
}
