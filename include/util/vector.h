#pragma once

#include "../allocator.h"
#include "../secure_object.h"
#include <vector>


namespace pgp {

    /**
     *  Alias for a vector using secure storage
     */
    template <typename T>
    using vector = secure_object<std::vector<T, allocator<T>>>;

}
