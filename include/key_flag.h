#pragma once

#include <boost/utility/string_view.hpp>


namespace pgp {

    /**
     *  Enum containing the possible flags in a key_flags packet
     */
    enum class key_flag : uint8_t
    {
        certification             = 0x01,
        signing                   = 0x02,
        encryption_communications = 0x04,
        encryption_storage        = 0x08,
        split_key                 = 0x10,
        authentication            = 0x20,
        group_key                 = 0x80
    };

    /**
     *  Get a description of the key flag
     *
     *  @param  flag    The key flag
     *  @return The description of the key flag
     */
    constexpr boost::string_view key_flag_description(key_flag flag) noexcept
    {
        // check the provided flag
        switch (flag) {
            case key_flag::certification:             return "certification";
            case key_flag::signing:                   return "signing";
            case key_flag::encryption_communications: return "encryption of communications";
            case key_flag::encryption_storage:        return "encryption of storage";
            case key_flag::split_key:                 return "key may be split";
            case key_flag::authentication:            return "authentication";
            case key_flag::group_key:                 return "private component may be shared";
        }
    }

}
