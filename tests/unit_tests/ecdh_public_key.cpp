#include <gtest/gtest.h>
#include "../key_template.h"
#include "../../ecdh_public_key.h"


TEST(ecdh_public_key, test)
{
    using key_type = pgp::ecdh_public_key;
    tests::key_test<key_type,
        tests::parameters::oid<&key_type::curve>,
        tests::parameters::mpi<&key_type::Q>,
        tests::parameters::hashalgo<&key_type::hash_function>,
        tests::parameters::keyalgo<&key_type::algorithm>>();
}
