#pragma once

#include "util/span.h"
#include <type_traits>
#include <cstddef>
#include <cstdint>


namespace pgp {

    /**
     *  Fallback struct for types not qualifying as
     *  a decoder type
     */
    template <typename T, typename = void>
    struct is_decoder : std::false_type {};

    /**
     *  Structure matching on valid decoders
     */
    template<typename T>
    struct is_decoder<T, std::void_t<
        decltype(std::declval<T>().splice(0)),  // note: cannot check for a valid decoder return type, template recursion
        std::enable_if_t<std::is_same_v<bool,                   decltype(std::declval<T>().empty())                             >>,
        std::enable_if_t<std::is_same_v<size_t,                 decltype(std::declval<T>().size())                              >>,
        std::enable_if_t<std::is_same_v<uint8_t,                decltype(std::declval<T>().peek_bits(0))                        >>,
        std::enable_if_t<std::is_same_v<uint8_t,                decltype(std::declval<T>().extract_bits(0))                     >>,
        std::enable_if_t<std::is_same_v<uint8_t,                decltype(std::declval<T>().template peek_number<uint8_t>())     >>,
        std::enable_if_t<std::is_same_v<uint8_t,                decltype(std::declval<T>().template extract_number<uint8_t>())  >>,
        std::enable_if_t<std::is_same_v<span<const uint8_t>,    decltype(std::declval<T>().template extract_blob<uint8_t>(0))   >>
    >> : std::true_type {};

    /**
     *  Value alias for the decoder structs
     */
    template <typename T>
    constexpr bool is_decoder_v = is_decoder<T>::value;

}
