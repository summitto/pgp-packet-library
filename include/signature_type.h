#pragma once

#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  Enum containing the various signature types
     */
    enum class signature_type : uint8_t
    {
        binary_document                                 = 0x00,
        canonical_text_document                         = 0x01,
        standalone                                      = 0x02,
        generic_user_id_and_public_key_certification    = 0x10,
        persona_user_id_and_public_key_certification    = 0x11,
        casual_user_id_and_public_key_certification     = 0x12,
        positive_user_id_and_public_key_certification   = 0x13,
        subkey_binding                                  = 0x18,
        primary_key_binding                             = 0x19,
        key_signature                                   = 0x1f,
        key_revocation                                  = 0x20,
        subkey_revocation                               = 0x28,
        certification_revocation                        = 0x30,
        timestamp                                       = 0x40,
        third_party_confirmation                        = 0x50
    };

    /**
     *  Get a description of the signature type
     *
     *  @param  type    The signature type
     *  @return The description of the signature type
     */
    constexpr boost::string_view signature_type_description(signature_type type) noexcept
    {
        // check the provided type
        switch (type) {
            case signature_type::binary_document:                               return "binary document signature";
            case signature_type::canonical_text_document:                       return "canonical text document signature";
            case signature_type::standalone:                                    return "standalone signature";
            case signature_type::generic_user_id_and_public_key_certification:  return "generic certification of user id and public-key packet";
            case signature_type::persona_user_id_and_public_key_certification:  return "persona certification of user id and public-key packet";
            case signature_type::casual_user_id_and_public_key_certification:   return "casual certification of user id and public-key packet";
            case signature_type::positive_user_id_and_public_key_certification: return "positive certification of user id and public-key packet";
            case signature_type::subkey_binding:                                return "subkey binding signature";
            case signature_type::primary_key_binding:                           return "primary key binding signature";
            case signature_type::key_signature:                                 return "key signature";
            case signature_type::key_revocation:                                return "key recovation signature";
            case signature_type::subkey_revocation:                             return "subkey revocation signature";
            case signature_type::certification_revocation:                      return "certification revocation signature";
            case signature_type::timestamp:                                     return "timestamp signature";
            case signature_type::third_party_confirmation:                      return "third-party confirmation signature";
        }
    }

}
