#include <eosio/chain/name.hpp>
#include <eosio/chain/block_timestamp.hpp>

#include <pybind11/pybind11.h>
#include <pybind11/operators.h>


namespace py = pybind11;

namespace chain = eosio::chain;


PYBIND11_MODULE(py_eosio, m) {

    py::class_<chain::name>(m, "Name")
        .def(py::init([] () {
            return new chain::name();
        }))
        .def(py::init([] (std::string str) {
            return new chain::name(str);
        }))
        .def(py::init([] (uint64_t v) {
            return new chain::name(v);
        }))
        .def("__str__", &chain::name::to_string)
        .def("as_int",  &chain::name::to_uint64_t)
        .def(py::self  < py::self)
        .def(py::self  > py::self)
        .def(py::self <= py::self)
        .def(py::self >= py::self)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self == uint64_t())
        .def(py::self != uint64_t());

    py::class_<fc::microseconds>(m, "Microseconds")
        .def(py::init([] (int64_t c) {
            return new fc::microseconds(c);
        }))
        .def(py::self  + py::self)
        .def(py::self  - py::self)
        .def(py::self  > py::self)
        .def(py::self >= py::self)
        .def(py::self  < py::self)
        .def(py::self <= py::self)
        .def(py::self += py::self)
        .def(py::self -= py::self)
        .def("count", &fc::microseconds::count)
        .def("seconds", &fc::microseconds::to_seconds);

    py::class_<fc::time_point>(m, "TimePoint")
        .def(py::init([] (fc::microseconds e) {
            return new fc::time_point(e);
        }))
        .def("now", (fc::time_point (*)()) &fc::time_point::now)
        .def("max", &fc::time_point::maximum)
        .def("min", &fc::time_point::min)
        .def("since_epoch", &fc::time_point::time_since_epoch)
        .def("sec_since_epoch", &fc::time_point::sec_since_epoch)
        .def(py::self  > py::self)
        .def(py::self >= py::self)
        .def(py::self  < py::self)
        .def(py::self <= py::self)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self += fc::microseconds())
        .def(py::self -= fc::microseconds())
        .def(py::self  + fc::microseconds())
        .def(py::self  - fc::microseconds());

    // py::class_<chain::block_timestamp_type>(m, "BlockTimestamp"
    //     .def(py::init([] (uint32_t s) {
    //         return new chain::block_timestamp_type(s);
    //     }))

}
