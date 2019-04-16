#include <gtest/gtest.h>
#include "../key_template.h"
#include "../../eddsa_public_key.h"


TEST(eddsa_public_key, test)
{
    using key_type = pgp::eddsa_public_key;
    tests::key_test<key_type,
        tests::parameters::oid<&key_type::curve>,
        tests::parameters::mpi<&key_type::Q>>();
}
