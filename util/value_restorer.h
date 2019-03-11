#pragma once


namespace util {

    /**
     *  Helper class to call a change-restoring function unless the changes are
     *  committed
     */
    template <typename Func>
    class Restorer {
    public:
        Restorer(Func func):
            _func{ func } {}

        /**
         *  If commit() was not called, the restore function will be called.
         */
        ~Restorer()
        {
            if (!committed) {
                _func();
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
        Func _func;
        bool committed = false;
    };

}
