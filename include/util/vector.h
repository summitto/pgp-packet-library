#pragma once

#include "../allocator.h"
#include <vector>


namespace pgp {

    /**
     *  Alias for a vector using secure storage
     */
    template <typename T>
    using vector = std::vector<T, allocator<T>>;

}
