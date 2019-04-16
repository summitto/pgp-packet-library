#include "key_template.h"


namespace tests {
    namespace detail {
        std::ostream& operator<<(std::ostream &os, const gsl::span<const uint8_t> &sp)
        {
            os << '{';
            bool first = true;
            for (const uint8_t byte : sp) {
                if (first) first = false;
                else os << ", ";
                os << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
            }
            os << '}';
            return os;
        }

    }
    namespace parameters::generate {
        thread_local device_random_engine random_engine;

        pgp::multiprecision_integer mpi()
        {
            std::uniform_int_distribution<int> length_distr(1, 600);
            std::uniform_int_distribution<uint8_t> distr(0, 25);

            int length = length_distr(random_engine);
            std::vector<uint8_t> data(length);
            for (uint8_t &elem : data) {
                elem = distr(random_engine);
            }

            return pgp::multiprecision_integer{data};
        }

        pgp::curve_oid oid()
        {
            return random_choice<pgp::curve_oid>({
                pgp::curve_oid::ed25519(),
                pgp::curve_oid::curve_25519(),
            });
        }

        pgp::hash_algorithm hashalgo()
        {
            return random_choice<pgp::hash_algorithm>({
                pgp::hash_algorithm::md5,
                pgp::hash_algorithm::sha1,
                pgp::hash_algorithm::ripemd160,
                pgp::hash_algorithm::sha256,
                pgp::hash_algorithm::sha384,
                pgp::hash_algorithm::sha512,
                pgp::hash_algorithm::sha224,
            });
        }

        pgp::symmetric_key_algorithm keyalgo()
        {
            return random_choice<pgp::symmetric_key_algorithm>({
                pgp::symmetric_key_algorithm::plaintext,
                pgp::symmetric_key_algorithm::idea,
                pgp::symmetric_key_algorithm::triple_des,
                pgp::symmetric_key_algorithm::cast5,
                pgp::symmetric_key_algorithm::blowfish,
                pgp::symmetric_key_algorithm::aes128,
                pgp::symmetric_key_algorithm::aes192,
                pgp::symmetric_key_algorithm::aes256,
                pgp::symmetric_key_algorithm::twofish256,
                pgp::symmetric_key_algorithm::camellia128,
                pgp::symmetric_key_algorithm::camellia192,
                pgp::symmetric_key_algorithm::camellia256,
            });
        }
    }
}
