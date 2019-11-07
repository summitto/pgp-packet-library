#pragma once

#include <utility>


namespace util {

    /**
     *  Helper class to call a change-restoring function unless the changes are
     *  committed using commit()
     */
    template <typename Rollback>
    class transaction {
    public:
        explicit transaction(Rollback rollback):
            _rollback{ std::forward<Rollback>(rollback) } {}

        /**
         *  Copy and move constructors
         */
        transaction(const transaction &other) = default;
        transaction(transaction &&other) noexcept = default;

        /**
         *  Assignment operators
         */
        transaction &operator=(const transaction &other) noexcept = default;
        transaction &operator=(transaction &&other) noexcept = default;

        /**
         *  If commit() was not called, the restore function will be called.
         */
        ~transaction()
        {
            if (!committed) {
                _rollback();
            }
        }

        /**
         *  Prevent the restore function from being called upon destruction.
         */
        void commit()
        {
            committed = true;
        }

    private:
        using rollback_t = std::remove_cv_t<std::remove_reference_t<Rollback>>;

        rollback_t _rollback;
        bool committed = false;
    };

}
