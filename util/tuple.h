#pragma once

/**
 *  This file is only necessary to deal with implementations
 *  missing the required make_from_tuple functionality in the
 *  STL.
 *
 *  When the STL implementation catches up, util::make_from_tuple
 *  can be changed to std::make_from_tuple, and this file can
 *  then be deleted.
 */

namespace {

    /**
     *  Private helper function to construct the type
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

}
 
namespace util {

    /**
     *  Create a type T from a tuple of parameters
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

}
