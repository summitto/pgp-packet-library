#include <type_traits>
#include <cstdio>

namespace pgp {

    /**
     *  Class for managing the lifetime of a pointer
     *  that needs to be freed using a specific
     *  c-function. The function to call is part
     *  of the pointer specification
     */
    template <typename R, typename T, R(*CALLBACK)(T*)>
    class raii_pointer
    {
        public:
            /**
             *  Empty constructor
             */
            raii_pointer() = default;

            /**
             *  Constructor handling a specific pointer
             *
             *  @param  pointer     The pointer to manage
             */
            raii_pointer(T *pointer) noexcept :
                _pointer{ pointer }
            {}

            /**
             *  Destructor
             */
            ~raii_pointer()
            {
                // execute the provided callback
                (*CALLBACK)(_pointer);
            }

            /**
             *  Cast to the underlying type
             *  @return The pointer we manage
             */
            operator T *() noexcept
            {
                // return the stored pointer
                return _pointer;
            }

            /**
             *  Retrieve member from the pointer
             *  @return The pointer we manage
             */
            T *operator->() noexcept
            {
                // return the stored pointer
                return _pointer;
            }

            /**
             *  Are we holding a valid pointer
             *  @return Whether we are not a nullptr
             */
            operator bool() const noexcept
            {
                // do we have a valid pointer?
                return _pointer != nullptr;
            }

            /**
             *  Check whether we are a nullptr
             *  @return Whether we are empty
             */
            bool operator==(std::nullptr_t) const noexcept
            {
                // check whether the pointer is invalid
                return _pointer == nullptr;
            }
        private:
            T   *_pointer{ nullptr };
    };

    namespace detail {

        template <class T> struct raii_pointer_type_helper;

        template <class R, class T>
        struct raii_pointer_type_helper<R(*)(T*)>
        {
            using return_type = R;
            using argument_type = T;
        };

    }

    template <auto F>
    auto make_raii_pointer(typename detail::raii_pointer_type_helper<decltype(F)>::argument_type *pointer)
    {
        using helper = detail::raii_pointer_type_helper<decltype(F)>;
        return raii_pointer<typename helper::return_type, typename helper::argument_type, F>{ pointer };
    }
}
