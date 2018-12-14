#include "public_key.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     *  @throws TODO
     */
    public_key::public_key(decoder &parser) :
        _version{ parser },
        _creation_time{ parser.extract_number<uint32_t>() },
        _algorithm{ parser.extract_number<uint8_t>() }
    {
        // retrieve the number of key components we need
        auto component_count = public_key_components_in_algorithm(algorithm());

        // allocate memory for the components
        _components.reserve(component_count);

        // and read all of them
        while (_components.size() < component_count) {
            // add another component
            _components.emplace_back(parser);
        }
    }

    /**
     *  Get the creation time
     *  @return UNIX timestamp with key creation time
     */
    uint32_t public_key::creation_time() const noexcept
    {
        // return the creation time of the key
        return _creation_time;
    }

    /**
     *  Retrieve the key algorithm
     *  @return The algorithm used in the key
     */
    public_key_algorithm public_key::algorithm() const noexcept
    {
        // return the stored algorithm of the key
        return _algorithm;
    }

    /**
     *  Retrieve the components in the key
     *  @return All the key components
     */
    gsl::span<const multiprecision_integer> public_key::components() const noexcept
    {
        // return the stored components
        return _components;
    }

}
