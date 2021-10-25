#include <eosio/eosio.hpp>
#include <eosio/system.hpp>
#include <eosio/singleton.hpp>

using namespace eosio;

class [[eosio::contract]] testcontract : public contract {
    public:
        using contract::contract;

        testcontract(name receiver, name code, datastream<const char*> ds) :
            contract(receiver, code, ds),
            cfg(receiver, receiver.value)
            {}

        [[eosio::action]]
        void testmultisig(name a, name b); 

        [[eosio::action]]
        void initcfg(uint64_t val);

        [[eosio::action]]
        void timestamp();

    private:

        struct [[eosio::table]] config {
            uint128_t value;
            uint64_t primary_key() const { return (uint64_t)value; }
        };

        using conf_type = eosio::singleton<"config"_n, config>;
        conf_type cfg;

};
