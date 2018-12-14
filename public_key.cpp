#include "public_key.h"

#include <iostream>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     *  @throws std::out_of_range
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
            std::cout << "Parsing component " << _components.size() << std::endl;
            _components.emplace_back(parser);
        }
    }

    /**
     *  Constructor
     *
     *  @param  creation_time   UNIX timestamp the key was created at
     *  @param  algorithm       The key algorithm used
     *  @param  components      The key components
     *  @throws std::runtime_error
     */
    public_key::public_key(uint32_t creation_time, public_key_algorithm algorithm, gsl::span<const multiprecision_integer> components) :
        _version{},
        _creation_time{ creation_time },
        _algorithm{ algorithm },
        _components{ components.begin(), components.end() }
    {}

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

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void public_key::encode(encoder &writer) const
    {
        // write out all the components of the key
        _version.encode(writer);
        writer.insert_number(_creation_time);
        writer.insert_enum(_algorithm);

        // iterate over the components
        for (auto &component : _components) {
            // add it to the encoder
            component.encode(writer);
        }
    }

}
