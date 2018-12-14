#pragma once

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

}
