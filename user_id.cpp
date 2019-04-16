#include "user_id.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The parser to decode data from
     */
    user_id::user_id(decoder &parser) :
        user_id{ parser.extract_blob<char>(parser.size()) }
    {}

    /**
     *  Constructor
     *
     *  @param  id      The user id to use
     */
    user_id::user_id(gsl::span<const char> id) noexcept :
        _id{ id.data(), static_cast<std::size_t>(id.size()) }
    {}

    /**
     *  Constructor
     *
     *  @param  id      The user id to use
     */
    user_id::user_id(std::string id) noexcept :
        _id{ std::move(id) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool user_id::operator==(const user_id &other) const noexcept
    {
        return id() == other.id();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool user_id::operator!=(const user_id &other) const noexcept
    { return !(*this == other); }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     *  @throws std::runtime_error for unknown key types
     */
    size_t user_id::size() const noexcept
    {
        // retrieve the size of the id
        return _id.size();
    }

    /**
     *  Retrieve the user id
     *
     *  @return The user id
     */
    const std::string &user_id::id() const noexcept
    {
        // return the stored id
        return _id;
    }

}
