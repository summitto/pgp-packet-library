#include "eddsa_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  curve   The curve object identifier
     *  @param  Q       The public curve point Q
     */
    eddsa_public_key::eddsa_public_key(curve_oid curve, multiprecision_integer Q) noexcept :
        _curve{ std::move(curve) },
        _Q{ std::move(Q) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool eddsa_public_key::operator==(const eddsa_public_key &other) const noexcept
    {
        return curve() == other.curve() && Q() == other.Q();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool eddsa_public_key::operator!=(const eddsa_public_key &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t eddsa_public_key::size() const noexcept
    {
        // we need to store the curve oid and the curve point
        return _curve.size() + _Q.size();
    }

    /**
     *  Retrieve the curve object identifier
     *
     *  @return The curve object identifier
     */
    const curve_oid &eddsa_public_key::curve() const noexcept
    {
        // return the curve object identifier
        return _curve;
    }

    /**
     *  Retrieve the public curve point Q
     *
     *  @return The public curve point Q, in compressed format
     */
    const multiprecision_integer &eddsa_public_key::Q() const noexcept
    {
        // return the public point
        return _Q;
    }

}
