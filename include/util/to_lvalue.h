#pragma once


namespace util {

    /**
     *  This hacky function converts rvalue references
     *  into lvalue references
     */
    template <class T>
    constexpr T& to_lvalue(T &&value)
    {
        // return the value
        return value;
    }

}
