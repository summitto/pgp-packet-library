#pragma once


#if __has_include(<span>)

#include <span>

namespace pgp {
    using std::span;
}

#else

#include <gsl/span>

namespace pgp {
    using gsl::span;
}

#endif
