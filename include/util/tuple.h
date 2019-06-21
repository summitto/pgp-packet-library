#pragma once

/**
 *  This file is only necessary to deal with implementations missing some
 *  required functionality in the STL.
 *
 *  When the STL implementation catches up, calls to util::* functions declared
 *  in this file can be changed to the corresponding std::* functions, and this
 *  file can then be deleted.
 */

namespace {

    /**
     *  Private helper function to construct the type
     *
     *  Source: https://en.cppreference.com/w/cpp/utility/make_from_tuple
     *
     *  @param  tuple   The tuple to construct from
     *  @return The constructed type T
     */
    template <class T, class Tuple, std::size_t... I>
    constexpr T make_from_tuple_impl( Tuple&& tuple, std::index_sequence<I...> )
    {
        // construct with all items from the tuple
        return T(std::get<I>(std::forward<Tuple>(tuple))...);
    }

    /**
     *  Private helper function to invoke the function
     *
     *  Source: https://en.cppreference.com/w/cpp/utility/apply
     *
     *  @param  f       The function to invoke
     *  @param  t       The tuple with the arguments to the function
     *  @return The return value of the invoked function
     */
    template <class F, class Tuple, std::size_t... I>
    constexpr decltype(auto) apply_impl(F&& f, Tuple&& t, std::index_sequence<I...>)
    {
        // call the Callable using std::invoke with all items from the tuple
        return std::invoke(std::forward<F>(f), std::get<I>(std::forward<Tuple>(t))...);
    }

}
 
namespace util {

    /**
     *  Create a type T from a tuple of parameters
     *
     *  Adapted from: https://en.cppreference.com/w/cpp/utility/make_from_tuple
     *
     *  @param  tuple   The tuple to create from
     *  @return The constructed type T
     */
    template <class T, class Tuple>
    constexpr T make_from_tuple(Tuple&& tuple)
    {
        // use the implementation, providing the index sequence into the tuple elements
        return make_from_tuple_impl<T>(std::forward<Tuple>(tuple), std::make_index_sequence<std::tuple_size<std::remove_reference_t<Tuple>>::value>{});
    }

    /**
     *  Invoke a Callable object with a tuple of arguments.
     *
     *  Adapted from: https://en.cppreference.com/w/cpp/utility/apply
     *
     *  @param  f       The function to invoke
     *  @param  t       The tuple with the arguments to the function
     *  @return The return value of the invoked function
     */
    template <class F, class Tuple>
    constexpr decltype(auto) apply(F&& f, Tuple&& t)
    {
        // use the implementation, providing the index sequence into the tuple elements
        return apply_impl(
            std::forward<F>(f), std::forward<Tuple>(t),
            std::make_index_sequence<std::tuple_size<std::remove_reference_t<Tuple>>::value>{}
        );
    }

}
