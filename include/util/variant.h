#pragma once


#ifdef USE_MPARK_VARIANT

#include <mpark/variant.hpp>

namespace pgp {
    using mpark::variant;
    using mpark::in_place_type_t;
    using mpark::get;
    using mpark::visit;
}

#else

#include <variant>

namespace pgp {
    using std::variant;
    using std::in_place_type_t;
    using std::get;
    using std::visit;
}

#endif
