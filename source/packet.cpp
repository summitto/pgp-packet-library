#include "packet.h"


namespace pgp {

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool packet::operator==(const packet &other) const noexcept
    {
        return body() == other.body();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool packet::operator!=(const packet &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Retrieve the packet tag
     *  @return The packet tag, as described in https://tools.ietf.org/html/rfc4880#section-4.3
     */
    packet_tag packet::tag() const noexcept
    {
        // the tag to return
        packet_tag result;

        // retrieve the body
        visit([&result](auto &body) {
            // retrieve the tag from the body
            result = body.tag();
        }, _body);

        // return the retrieved tag
        return result;
    }

    /**
     *  Retrieve the body length
     *
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t packet::size() const
    {
        // the body size to return
        uint32_t result;

        // retrieve the body
        visit([&result](auto &body) {
            // retrieve the size from the body
            result = util::narrow_cast<uint32_t>(body.size());
        }, _body);

        // is the packet compatible with the old format?
        if (packet_tag_compatible_with_old_format(tag())) {
            // determine the storage type used
            if (result > 65535) {
                // we need four bytes for the body length, plus
                // an additional byte for storing the packet tag
                return result + 1 + 4;
            } else if (result > 255) {
                // we need two bytes for the body length, plus an
                // additional byte for storing the packet tag
                return result + 1 + 2;
            } else {
                // we need a single byte for the body length, plus
                // an additional byte for storing the packet tag
                return result + 1 + 1;
            }
        } else {
            // we need one byte for the tag and a variable number
            // to store the length of the body data
            return result + 1 + variable_number{ result }.size();
        }
    }

    /**
     *  Retrieve the decoded packet
     *
     *  @return The packet that was parsed
     */
    const packet::packet_variant &packet::body() const noexcept
    {
        // return the decoded body
        return _body;
    }

}
