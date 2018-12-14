#pragma once


namespace pgp {

    /**
     *  The available algorithms for the key
     */
    enum class public_key_algorithm : uint8_t
    {
        rsa_encrypt_or_sign     =  0,
        rsa_encrypt_only        =  1,
        rsa_sign_only           =  2,
        elgamal_encrypt_only    = 16,
        dsa                     = 17
    };

    /**
     *  Retrieve the number of key components
     *  for the specific algorithm
     *
     *  @param  algorithm   The key algorithm type
     *  @return Number of components in the key
     */
    constexpr size_t public_key_components_in_algorithm(public_key_algorithm algorithm) noexcept
    {
        // check the algorithm type
        switch (algorithm) {
            case public_key_algorithm::rsa_encrypt_or_sign:
            case public_key_algorithm::rsa_encrypt_only:
            case public_key_algorithm::rsa_sign_only:
                return 2;
            case public_key_algorithm::elgamal_encrypt_only:
                return 3;
            case public_key_algorithm::dsa:
                return 4;
            default:
                return 0;
        }
    }

}
