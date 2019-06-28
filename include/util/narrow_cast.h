#pragma once


namespace util {

    /**
     *  Searchable way to do narrow casts of values
     *
     *  @param u          The value to narrow
     *  @return The narrowed value
     */
    template <class T, class U>
    constexpr T narrow_cast(U&& u) noexcept
    {
        return static_cast<T>(std::forward<U>(u));
    }

}
