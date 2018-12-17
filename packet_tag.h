#pragma once

#include <type_traits>
#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  Enum with all the valid packet tags
     */
    enum class packet_tag : uint8_t
    {
        reserved                                                =  0,
        public_key_encrypted_session_key                        =  1,
        signature                                               =  2,
        symmetric_key_encrypted_session_key                     =  3,
        one_pass_signature                                      =  4,
        secret_key                                              =  5,
        public_key                                              =  6,
        secret_subkey                                           =  7,
        compressed_data                                         =  8,
        symmetrically_encrypted_data                            =  9,
        marker_packet                                           = 10,
        literal_data                                            = 11,
        trust_packet                                            = 12,
        user_id                                                 = 13,
        public_subkey                                           = 14,
        user_attribute                                          = 17,
        symmetrically_encrypted_and_integrity_protected_data    = 18,
        modification_detection_code                             = 19
    };

    /**
     *  Get a description of the packet tag
     *
     *  @param  tag     The packet tag to get a description for
     *  @return The packet tag to describe
     */
    constexpr boost::string_view packet_tag_description(packet_tag tag) noexcept
    {
        // check the provided tag
        switch (tag) {
            case packet_tag::reserved:                                              return "reserved tag - do not use";
            case packet_tag::public_key_encrypted_session_key:                      return "public key encrypted session key packet";
            case packet_tag::signature:                                             return "signature packet";
            case packet_tag::symmetric_key_encrypted_session_key:                   return "symmetric key encrypted session key packet";
            case packet_tag::one_pass_signature:                                    return "one pass signature packet";
            case packet_tag::secret_key:                                            return "secret key packet";
            case packet_tag::public_key:                                            return "public key packet";
            case packet_tag::secret_subkey:                                         return "secret subkey packet";
            case packet_tag::compressed_data:                                       return "compressed data packet";
            case packet_tag::symmetrically_encrypted_data:                          return "symmetrically encrypted data packet";
            case packet_tag::marker_packet:                                         return "marker packet";
            case packet_tag::literal_data:                                          return "literal data packet";
            case packet_tag::trust_packet:                                          return "trust packet";
            case packet_tag::user_id:                                               return "user id packet";
            case packet_tag::public_subkey:                                         return "public subkey packet";
            case packet_tag::user_attribute:                                        return "user attribute packet";
            case packet_tag::symmetrically_encrypted_and_integrity_protected_data:  return "symmetrically encrypted and integrity protected data packet";
            case packet_tag::modification_detection_code:                           return "modification detection code";
        };
    }

    /**
     *  Check whether a packet tag is compatible with the
     *  old package format
     *
     *  @param  tag     The packet tag to check
     *  @return Can the tag be represented in the old format
     */
    constexpr bool packet_tag_compatible_with_old_format(packet_tag tag) noexcept
    {
        // the old format uses only four bits to represent the tag
        // so any tag using more than this is not compatible
        return (0b11110000 & static_cast<typename std::underlying_type_t<packet_tag>>(tag)) == 0;
    }

}
