#pragma once


namespace util {

    /**
     *  Helper class to call a change-restoring function unless the changes are
     *  committed using commit()
     */
    template <typename RestoreCallback>
    class transaction {
    public:
        transaction(RestoreCallback restore_callback):
            _restore_callback{ restore_callback } {}

        /**
         *  If commit() was not called, the restore function will be called.
         */
        ~transaction()
        {
            if (!committed) {
                _restore_callback();
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
        RestoreCallback _restore_callback;
        bool committed = false;
    };

}
