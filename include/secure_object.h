#pragma once

#include <sodium/utils.h>


namespace pgp {

    /**
     *  A class that explicitly locks and erases memory
     */
    template <typename base_t>
    class secure_object : public base_t
    {
        public:
            /**
             *  Default constructor
             */
            secure_object()
            {
                // lock memory
                lock();
            }

            /**
             *  Constructor
             *
             *  @param  parameter   The first parameter
             *  @param  parameters  Zero or more additional parameters
             */
            template <typename T, typename... arguments>
            explicit secure_object(T&& parameter, arguments&&... parameters) :
                base_t{ (lock(), std::forward<T>(parameter)), std::forward<arguments>(parameters)... }
            {}

            /**
             *  Copy constructor
             *
             *  @param  that        The secure object to copy
             */
            secure_object(const secure_object<base_t> &that) :
                base_t{ (lock(), that) }
            {}

            /**
             *  Move constructor
             *
             *  @param  that        The secure object to move
             */
            secure_object(secure_object<base_t> &&that) :
                base_t{ (lock(), std::move(that)) }
            {}

            /**
             *  Destructor
             */
            ~secure_object()
            {
                // first destruct the managed object
                this->~base_t();

                // zero out the memory and unlock it
                sodium_memzero(this, sizeof(*this));
                sodium_munlock(this, sizeof(*this));

                // default construct the base again
                // so that the implicit destructor
                // coming after us runs correctly
                new (this) base_t{};
            }

            /**
             *  Copy assignment
             *
             *  @param  that    The secure object to copy
             *  @return Same object for chaining
             */
            secure_object<base_t> &operator=(const secure_object<base_t> &that)
            {
                // invoke base class copy operator and allow chaining
                base_t::operator=(that);
                return *this;
            }

            /**
             *  Move assignment
             *
             *  @param  that    The secure object to copy
             *  @return Same object for chaining
             */
            secure_object<base_t> &operator=(secure_object<base_t> &&that)
            {
                // invoke base class move operator and allow chaining
                base_t::operator=(std::move(that));
                return *this;
            }
        private:
            /**
             *  Lock the memory
             */
            void lock()
            {
                // ensure the data is locked so it is
                // not swapped to disk in low-memory
                sodium_mlock(this, sizeof(*this));
            }
    };

}
