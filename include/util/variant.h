#pragma once


#ifdef USE_MPARK_VARIANT

#include <mpark/variant.hpp>

namespace pgp {
    using mpark::variant;
    using mpark::in_place_type_t;
    using mpark::get;
    using mpark::visit;
    using mpark::holds_alternative;
    using mpark::swap;
    using mpark::operator==;
    using mpark::operator!=;
    using mpark::operator>;
    using mpark::operator<;
    using mpark::operator<=;
    using mpark::operator>=;
}

#else

#include <variant>

namespace pgp {
    using std::variant;
    using std::in_place_type_t;
    using std::get;
    using std::visit;
    using std::holds_alternative;
    using std::swap;
    using std::operator==;
    using std::operator!=;
    using std::operator>;
    using std::operator<;
    using std::operator<=;
    using std::operator>=;
}

#endif
