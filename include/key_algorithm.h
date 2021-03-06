#pragma once

#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  The available algorithms for the key
     */
    enum class key_algorithm : uint8_t
    {
        rsa_encrypt_or_sign     =  1,
        rsa_encrypt_only        =  2,
        rsa_sign_only           =  3,
        elgamal_encrypt_only    = 16,
        dsa                     = 17,
        ecdh                    = 18,
        ecdsa                   = 19,
        eddsa                   = 22
    };

    /**
     *  Get a description of the public key algorithm
     *
     *  @param  algorithm   The algorithm to get a description for
     *  @return The algorithm to describe
     */
    constexpr boost::string_view key_algorithm_description(key_algorithm algorithm) noexcept
    {
        // check the provided algorithm
        switch (algorithm) {
            case key_algorithm::rsa_encrypt_or_sign:    return "RSA (encrypt or sign)";
            case key_algorithm::rsa_encrypt_only:       return "RSA (encrypt only)";
            case key_algorithm::rsa_sign_only:          return "RSA (sign only)";
            case key_algorithm::elgamal_encrypt_only:   return "Elgamal (encrypt only)";
            case key_algorithm::dsa:                    return "DSA";
            case key_algorithm::ecdh:                   return "ECDH";
            case key_algorithm::ecdsa:                  return "ECDSA";
            case key_algorithm::eddsa:                  return "EdDSA";
        }
    }

}
