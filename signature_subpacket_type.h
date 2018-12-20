#pragma once

#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  Enum with all recognized signature subpacket types
     */
    enum class signature_subpacket_type : uint8_t
    {
        signature_creation_time             =  2,
        signature_expiration_time           =  3,
        exportable_certification            =  4,
        trust_signature                     =  5,
        regular_expression                  =  6,
        revocable                           =  7,
        key_expiration_time                 =  9,
        preferred_symmetric_algorithms      = 11,
        revocation_key                      = 12,
        issuer                              = 16,
        notation_data                       = 20,
        preferred_hash_algorithms           = 21,
        preferred_compression_algorithms    = 22,
        key_server_preferences              = 23,
        preferred_key_server                = 24,
        primary_user_id                     = 25,
        policy_uri                          = 26,
        key_flags                           = 27,
        signers_user_id                     = 28,
        revocation_reason                   = 29,
        features                            = 30,
        signature_target                    = 31,
        embedded_signature                  = 32,
        fingerprint                         = 33
    };

    /**
     *  Get a description of the signature subpacket type
     *
     *  @param  type    The signature subpacket type to get the description for
     *  @return The description for the subpacket type
     */
    constexpr boost::string_view signature_subpacket_type_description(signature_subpacket_type type) noexcept
    {
        // check the subpacket type
        switch (type) {
            case signature_subpacket_type::signature_creation_time:             return "signature creation time";
            case signature_subpacket_type::signature_expiration_time:           return "signature expiration time";
            case signature_subpacket_type::exportable_certification:            return "exportable certification";
            case signature_subpacket_type::trust_signature:                     return "trust signature";
            case signature_subpacket_type::regular_expression:                  return "regular expression";
            case signature_subpacket_type::revocable:                           return "revocable";
            case signature_subpacket_type::key_expiration_time:                 return "key expiration time";
            case signature_subpacket_type::preferred_symmetric_algorithms:      return "preferred symmetric algorithms";
            case signature_subpacket_type::revocation_key:                      return "revocation key";
            case signature_subpacket_type::issuer:                              return "issuer";
            case signature_subpacket_type::notation_data:                       return "notation data";
            case signature_subpacket_type::preferred_hash_algorithms:           return "preferred hash algorithms";
            case signature_subpacket_type::preferred_compression_algorithms:    return "preferred compression algorithms";
            case signature_subpacket_type::key_server_preferences:              return "key server preferences";
            case signature_subpacket_type::preferred_key_server:                return "preferred key server";
            case signature_subpacket_type::primary_user_id:                     return "primary user id";
            case signature_subpacket_type::policy_uri:                          return "policy uri";
            case signature_subpacket_type::key_flags:                           return "key flags";
            case signature_subpacket_type::signers_user_id:                     return "signer's user id";
            case signature_subpacket_type::revocation_reason:                   return "reason for revocation";
            case signature_subpacket_type::features:                            return "features";
            case signature_subpacket_type::signature_target:                    return "signature target";
            case signature_subpacket_type::embedded_signature:                  return "embedded signature";
            case signature_subpacket_type::fingerprint:                         return "fingerprint";
        }

        // other subpackets are unknown
        return "unknown signature subpacket";
    }

}
