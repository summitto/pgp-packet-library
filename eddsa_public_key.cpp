#include "eddsa_public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    eddsa_public_key::eddsa_public_key(decoder &parser) :
        _curve{ parser },
        _Q{ parser }
    {}

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

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void eddsa_public_key::encode(encoder &writer) const
    {
        // encode the curve id and public point
        _curve.encode(writer);
        _Q.encode(writer);
    }

}
