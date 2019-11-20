#pragma once

#include <sodium/utils.h>
#include <type_traits>
#include <new>


namespace pgp {

    /**
     *  Class for securely allocating and deallocating
     *  memory. Memory is prevented from being paged out
     *  and guard pages are placed right before and after
     *  the allocated memory to detect invalid access.
     */
    template <typename T>
    class allocator
    {
        public:
            /**
             *  Type aliases
             */
            using pointer       = T*;
            using const_pointer = const T*;
            using value_type    = T;

            /**
             *  Constructor
             */
            allocator() = default;

            /**
             *  Allocate memory for zero or more instances
             *  of `value_type`. The instances will not be
             *  initialized, the memory is initialized with
             *  0xdb for security reasons.
             *
             *  @param  count   Number of elements to allocate memory for
             *  @return Pointer to the allocated memory
             *  @throws std::bad_alloc
             */
            pointer allocate(size_t count)
            {
                // allocate secure memory
                auto *result = sodium_allocarray(count, sizeof(aligned_t));

                // check whether we got a valid pointer
                if (result == nullptr) {
                    // memory allocation failed
                    throw std::bad_alloc{};
                }

                // cast to the requested type
                return static_cast<pointer>(result);
            }

            /**
             *  Free memory previously allocated using
             *  this allocator. Does not destroy instances.
             *
             *  Guard pages are checked, and memory is cleared
             *  before release. Upon failure, no exceptions are
             *  thrown, the program simply terminates.
             *
             *  @param  address The address to free
             */
            void deallocate(pointer address, size_t) noexcept
            {
                // free the memory
                sodium_free(address);
            }

            /**
             *  Are we logically the same as the other
             *  given allocator?
             *
             *  @return The result of the comparison
             */
            constexpr bool operator==(const allocator<T> &) noexcept { return true;  }
            constexpr bool operator!=(const allocator<T> &) noexcept { return false; }
        private:
            // alias for an aligned buffer capable of holding one instance of value_type
            using aligned_t = std::aligned_storage_t<sizeof(value_type), alignof(value_type)>;
    };

}
