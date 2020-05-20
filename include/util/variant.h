#pragma once

#ifdef USE_MPARK_VARIANT

#define VARIANT_PROVIDER mpark
#include <mpark/variant.hpp>

#else

#define VARIANT_PROVIDER std
#include <variant>

#endif

namespace pgp {
    using VARIANT_PROVIDER::variant;
    using VARIANT_PROVIDER::in_place_type_t;
    using VARIANT_PROVIDER::get;
    using VARIANT_PROVIDER::visit;
    using VARIANT_PROVIDER::holds_alternative;
    using VARIANT_PROVIDER::swap;
    using VARIANT_PROVIDER::operator==;
    using VARIANT_PROVIDER::operator!=;
    using VARIANT_PROVIDER::operator>;
    using VARIANT_PROVIDER::operator<;
    using VARIANT_PROVIDER::operator<=;
    using VARIANT_PROVIDER::operator>=;
    using VARIANT_PROVIDER::bad_variant_access;
    using VARIANT_PROVIDER::variant_size;
    using VARIANT_PROVIDER::variant_size_v;
    using VARIANT_PROVIDER::monostate;
    using VARIANT_PROVIDER::variant_npos;
}
