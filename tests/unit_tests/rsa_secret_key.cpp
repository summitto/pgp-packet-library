#include <gtest/gtest.h>
#include "../key_template.h"
#include "rsa_secret_key.h"


TEST(rsa_secret_key, test)
{
    using key_type = pgp::rsa_secret_key;
    tests::key_test<key_type,
        tests::parameters::mpi<&key_type::d>,
        tests::parameters::mpi<&key_type::p>,
        tests::parameters::mpi<&key_type::q>,
        tests::parameters::mpi<&key_type::u>>();
}
