#include "key_template.h"


namespace tests {
    namespace detail {
        std::ostream& operator<<(std::ostream &os, const pgp::span<const uint8_t> &sp)
        {
            os << '{';
            bool first = true;
            for (const uint8_t byte : sp) {
                if (first) first = false;
                else os << ", ";
                os << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
            }
            os << '}';
            return os;
        }
    }
}
