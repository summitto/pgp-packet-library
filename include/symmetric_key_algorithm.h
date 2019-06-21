#pragma once

#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  The available symmetric key algorithms
     */
    enum class symmetric_key_algorithm : uint8_t
    {
        plaintext       =  0,
        idea            =  1,
        triple_des      =  2,
        cast5           =  3,
        blowfish        =  4,
        aes128          =  7,
        aes192          =  8,
        aes256          =  9,
        twofish256      = 10,
        camellia128     = 11,
        camellia192     = 12,
        camellia256     = 13
    };

    /**
     *  Get a description of the symmetric key algorithm
     *
     *  @param  algorithm   The algorithm to get a description for
     *  @return The description of the algorithm
     */
    constexpr boost::string_view symmetric_key_algorithm_description(symmetric_key_algorithm algorithm) noexcept
    {
        // check the given algorithm
        switch (algorithm) {
            case symmetric_key_algorithm::plaintext:    return "plaintext";
            case symmetric_key_algorithm::idea:         return "IDEA";
            case symmetric_key_algorithm::triple_des:   return "TripleDES";
            case symmetric_key_algorithm::cast5:        return "CAST5";
            case symmetric_key_algorithm::blowfish:     return "Blowfish";
            case symmetric_key_algorithm::aes128:       return "AES with 128-bit key";
            case symmetric_key_algorithm::aes192:       return "AES with 192-bit key";
            case symmetric_key_algorithm::aes256:       return "AES with 256-bit key";
            case symmetric_key_algorithm::twofish256:   return "Twofish with 256-bit key";
            case symmetric_key_algorithm::camellia128:  return "Camellia with 128-bit key";
            case symmetric_key_algorithm::camellia192:  return "Camellia with 192-bit key";
            case symmetric_key_algorithm::camellia256:  return "Camellia with 256-bit key";
        }

        // unknown algorithm found
        return "unknown symmetric key algorithm";
    }

}
