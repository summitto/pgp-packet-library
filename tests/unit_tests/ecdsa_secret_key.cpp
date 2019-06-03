#include <gtest/gtest.h>
#include "../key_template.h"
#include "../../ecdsa_secret_key.h"


TEST(ecdsa_secret_key, test)
{
    using key_type = pgp::ecdsa_secret_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::k>>();
}
