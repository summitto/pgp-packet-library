#pragma once

#include <gsl/span>
#include <stdexcept>
#include <boost/optional.hpp>
#include "packet_tag.h"
#include "decoder.h"


namespace pgp {

    /**
     *  Class for working with a single packet encoded
     *  according to the specification in RFC 4880
     *  @see: https://tools.ietf.org/html/rfc4880#section-4
     */
    class packet
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws TODO
             */
            packet(decoder &parser);

            /**
             *  Retrieve the packet type
             *  @return The packet type, as described in TODO
             */
            packet_tag type() const noexcept;

            /**
             *  Retrieve the body length
             *
             *  @note   If the body length is unknown, no size will be returned
             *  @return The number of bytes in the body of the packet
             */
            boost::optional<size_t> size() const noexcept;
        private:
            packet_tag              _type   { packet_tag::reserved  };  // the packet type
            boost::optional<size_t> _size   { 0                     };  // number of bytes in the body
    };

}
