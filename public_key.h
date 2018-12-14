#pragma once

#include "decoder.h"
#include "expected_number.h"
#include "public_key_algorithm.h"
#include "multiprecision_integer.h"


namespace pgp {

    /**
     *  Class for managing a public key
     */
    class public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws TODO
             */
            public_key(decoder &parser);

            /**
             *  Get the key version
             *  @return The key version format
             */
            constexpr uint8_t version() const noexcept
            {
                // extract the value version
                return _version.value();
            }

            /**
             *  Get the creation time
             *  @return UNIX timestamp with key creation time
             */
            uint32_t creation_time() const noexcept;

            /**
             *  Retrieve the key algorithm
             *  @return The algorithm used in the key
             */
            public_key_algorithm algorithm() const noexcept;

            /**
             *  Retrieve the components in the key
             *  @return All the key components
             */
            gsl::span<const multiprecision_integer> components() const noexcept;
        private:
            expected_number<uint8_t, 4>         _version;               // the expected key version format
            uint32_t                            _creation_time  { 0 };  // UNIX timestamp the key was created at
            public_key_algorithm                _algorithm      { 0 };  // the algorithm for creating the key
            std::vector<multiprecision_integer> _components;            // the algorithm-specific components of the key

    };
}
