#pragma once


#ifdef USE_GSL_SPAN

#include <gsl/span>

namespace pgp {
    using gsl::span;
}

#else

#include <span>

namespace pgp {
    using std::span;
}

#endif
