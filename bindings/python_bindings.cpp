#include <eosio/chain/name.hpp>
#include <eosio/chain/types.hpp>
#include <eosio/chain/block_timestamp.hpp>
#include <eosio/chain/block_header.hpp>

#include <pybind11/stl.h>
#include <pybind11/pybind11.h>
#include <pybind11/operators.h>


namespace py = pybind11;

namespace chain = eosio::chain;


PYBIND11_MODULE(py_eosio, m) {

    py::class_<fc::sha256>(m, "SHA256")
        .def(py::init([] (std::string hex) {
            return new fc::sha256(hex);
        }))
        .def("__str__", &fc::sha256::str)
        .def("data", [](const fc::sha256 &a) {
                return a.data();
        })
        .def("data_size", &fc::sha256::data_size)
        .def("hash_str", (fc::sha256 (*)()) &fc::sha256::hash<std::string>)
        .def("hash", (fc::sha256 (*)()) &fc::sha256::hash<fc::sha256>)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self >= py::self)
        .def(py::self  > py::self)
        .def(py::self  < py::self)
        .def("pop_count", &fc::sha256::pop_count)
        .def("clz", &fc::sha256::clz)
        .def("approx_log_32", &fc::sha256::approx_log_32)
        .def("set_to_inverse_approx_log_32", &fc::sha256::set_to_inverse_approx_log_32)
        .def("inverse_approx_log_32_double", (double (*)()) &fc::sha256::inverse_approx_log_32_double);

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
        .def("max", (fc::time_point (*)()) &fc::time_point::maximum)
        .def("min", (fc::time_point (*)()) &fc::time_point::min)
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

    py::class_<chain::block_timestamp_type>(m, "BlockTimestamp")
        .def(py::init([] (uint32_t s) {
            return new chain::block_timestamp_type(s);
        }))
        .def(py::init([] (fc::time_point t) {
            return new chain::block_timestamp_type(t);
        }))
        .def("max", (chain::block_timestamp_type (*)()) &chain::block_timestamp_type::maximum)
        .def("min", (chain::block_timestamp_type (*)()) &chain::block_timestamp_type::min)
        .def("next", &chain::block_timestamp_type::next)
        .def("as_time_point", &chain::block_timestamp_type::to_time_point)
        .def(py::self  > py::self)
        .def(py::self >= py::self)
        .def(py::self  < py::self)
        .def(py::self <= py::self)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def_readwrite("slot", &chain::block_timestamp_type::slot);

    py::class_<chain::block_header>(m, "BlockHeader")
        .def_readwrite("timestamp", &chain::block_header::timestamp)
        .def_readwrite("producer", &chain::block_header::producer)
        .def_readwrite("confirmed", &chain::block_header::confirmed)
        .def_readwrite("previous", &chain::block_header::previous)
        .def_readwrite("transaction_mroot", &chain::block_header::transaction_mroot)
        .def_readwrite("action_mroot", &chain::block_header::action_mroot);

}
