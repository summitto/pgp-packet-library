#pragma once

#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  The available hashing algorithms
     */
    enum class hash_algorithm : uint8_t
    {
        md5         =  1,
        sha1        =  2,
        ripemd160   =  3,
        sha256      =  8,
        sha384      =  9,
        sha512      = 10,
        sha224      = 11
    };

    /**
     *  Get a description of the hash algorithm
     *
     *  @param  algorithm   The algorithm to get a description for
     *  @return The description of the algorithm
     */
    constexpr boost::string_view hash_algorithm_description(hash_algorithm algorithm) noexcept
    {
        // check the given algorithm
        switch (algorithm) {
            case hash_algorithm::md5:       return "MD5";
            case hash_algorithm::sha1:      return "SHA1";
            case hash_algorithm::ripemd160: return "RIPEMD160";
            case hash_algorithm::sha256:    return "SHA256";
            case hash_algorithm::sha384:    return "SHA384";
            case hash_algorithm::sha512:    return "SHA512";
            case hash_algorithm::sha224:    return "SHA224";
        }
    }

}
