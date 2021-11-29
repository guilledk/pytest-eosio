#include <vector>

#include <eosio/chain/name.hpp>
#include <eosio/chain/types.hpp>
#include <eosio/chain/block_header.hpp>
#include <eosio/chain/block_timestamp.hpp>
#include <eosio/chain/protocol_feature_activation.hpp>


#include <pybind11/stl.h>
#include <pybind11/pybind11.h>
#include <pybind11/operators.h>


namespace py = pybind11;
namespace chain = eosio::chain;


using std::pair;
using std::vector;


PYBIND11_MODULE(py_eosio, root_mod) {

    py::module chain_mod = root_mod.def_submodule("chain");

    py::module time_mod = chain_mod.def_submodule("time");
    py::module types_mod = chain_mod.def_submodule("types");
    py::module crypto_mod = chain_mod.def_submodule("crypto");

    /*
     *
     * chain.time
     *
     */

    py::class_<fc::microseconds>(time_mod, "Microseconds")
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

    py::class_<fc::time_point>(time_mod, "TimePoint")
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

    /*
     *
     * chain.types
     *
     */

    py::class_<chain::weight_type>(types_mod, "Weight")
        .def(py::init([] (uint16_t v) {
            return new chain::weight_type(v);
        }));

    py::class_<chain::block_num_type>(types_mod, "BlockNum")
        .def(py::init([] (uint32_t v) {
            return new chain::block_num_type(v);
        }));

    py::class_<chain::share_type>(types_mod, "Share")
        .def(py::init([] (int64_t v) {
            return new chain::share_type(v);
        }));

    py::class_<chain::bytes>(types_mod, "Bytes")
        .def(py::init([] (vector<char> buf) {
            return new chain::bytes(buf);
        }));

    py::class_<chain::block_id_type>(types_mod, "BlockId")
        .def(py::init([] (std::string hex) {
            return new chain::block_id_type(hex);
        }));

    py::class_<chain::checksum_type>(types_mod, "Checksum")
        .def(py::init([] (std::string hex) {
            return new chain::checksum_type(hex);
        }));

    py::class_<chain::checksum160_type>(types_mod, "Checksum160")
        .def(py::init([] (std::string hex) {
            return new chain::checksum160_type(hex);
        }));

    py::class_<chain::checksum256_type>(types_mod, "Checksum256")
        .def(py::init([] (std::string hex) {
            return new chain::checksum256_type(hex);
        }));

    py::class_<chain::checksum512_type>(types_mod, "Checksum512")
        .def(py::init([] (std::string hex) {
            return new chain::checksum512_type(hex);
        }));

    py::class_<chain::transaction_id_type>(types_mod, "TransactionId")
        .def(py::init([] (std::string hex) {
            return new chain::transaction_id_type(hex);
        }));

    py::class_<chain::digest_type>(types_mod, "Digest")
        .def(py::init([] (std::string hex) {
            return new chain::digest_type(hex);
        }));

    py::class_<chain::signature_type>(types_mod, "Signature")
        .def(py::init())
        .def(py::init<const std::string&>())
        .def(py::init<const chain::signature_type&>())
        .def("to_string", [](const chain::signature_type &sig) {
            return sig.to_string();
        })
        .def("which", &chain::signature_type::which)
        .def("variable_size", &chain::signature_type::variable_size);

    py::class_<chain::extensions_type>(types_mod, "Extensions")
        .def(py::init([] (vector<pair<uint16_t,vector<char>>> exts) {
            return new chain::extensions_type(exts);
        }))
        .def("emplace_extension", [](
            chain::extensions_type &exts,
            uint16_t eid,
            vector<char>&& data
        ) {
            chain::emplace_extension(exts, eid, std::move(data));    
        });

    /*
     *
     * chain.crypto
     *
     */

    py::class_<fc::sha256>(crypto_mod, "SHA256")
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

    py::class_<fc::sha512>(crypto_mod, "SHA512")
        .def(py::init([] (std::string hex) {
            return new fc::sha512(hex);
        }))
        .def("__str__", &fc::sha512::str)
        .def("data", [](const fc::sha512 &a) {
                return a.data();
        })
        .def("data_size", &fc::sha512::data_size)
        .def("hash_str", (fc::sha512 (*)(const std::string&)) &fc::sha512::hash)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self >= py::self)
        .def(py::self  > py::self)
        .def(py::self  < py::self);

    py::class_<fc::ripemd160>(crypto_mod, "RIPEMD160")
        .def(py::init([] (std::string hex) {
            return new fc::ripemd160(hex);
        }))
        .def("__str__", &fc::ripemd160::str)
        .def("data", [](const fc::ripemd160 &a) {
                return a.data();
        })
        .def("data_size", &fc::ripemd160::data_size)
        .def("hash_str", (fc::ripemd160 (*)()) &fc::ripemd160::hash<std::string>)
        .def("hash_sha256", (fc::ripemd160 (*)()) &fc::ripemd160::hash<fc::sha256>)
        .def("hash_sha512", (fc::ripemd160 (*)()) &fc::ripemd160::hash<fc::sha512>)
        .def(py::self == py::self)
        .def(py::self != py::self)
        .def(py::self >= py::self)
        .def(py::self  > py::self)
        .def(py::self  < py::self);

    /*
     *
     * chain
     *
     */

    py::class_<chain::protocol_feature_activation>(root_mod, "ProtocolFeatureActivation")
        .def(py::init())
        .def(py::init<const vector<chain::digest_type>&>())
        .def("extension_id", &chain::protocol_feature_activation::extension_id)
        .def("enforce_unique", &chain::protocol_feature_activation::enforce_unique)
        .def("reflector_init", &chain::protocol_feature_activation::reflector_init)
        .def_readwrite("protocol_features", &chain::protocol_feature_activation::protocol_features);

    py::class_<chain::name>(root_mod, "Name")
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


    py::class_<chain::block_timestamp_type>(root_mod, "BlockTimestamp")
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

    py::class_<chain::block_header>(root_mod, "BlockHeader")
        .def(py::init())
        .def_readwrite("timestamp", &chain::block_header::timestamp)
        .def_readwrite("producer", &chain::block_header::producer)
        .def_readwrite("confirmed", &chain::block_header::confirmed)
        .def_readwrite("previous", &chain::block_header::previous)
        .def_readwrite("transaction_mroot", &chain::block_header::transaction_mroot)
        .def_readwrite("action_mroot", &chain::block_header::action_mroot)
        .def_readwrite("header_extensions", &chain::block_header::header_extensions)
        .def("digest", &chain::block_header::digest)
        .def("calculate_id", &chain::block_header::calculate_id)
        .def("block_num", &chain::block_header::block_num)
        .def("num_from_id", &chain::block_header::num_from_id);

    py::class_<
        chain::signed_block_header,
        chain::block_header
    >(root_mod, "SignedBlockHeader")
        .def(py::init())
        .def_readwrite("producer_signature", &chain::signed_block_header::producer_signature);
}
