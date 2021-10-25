#include "testcontract.hpp"

void testcontract::testmultisig(name a, name b) {
    require_auth(a);
    require_auth(b);
    auto entry = cfg.get_or_create(get_self(), config{0});
    entry.value = (uint128_t)a.value + (uint128_t)b.value; 
    cfg.set(entry, get_self());
}

void testcontract::initcfg(uint64_t val) {
    auto entry = cfg.get_or_create(get_self(), config{0});
    entry.value = val; 
    cfg.set(entry, get_self());
}

void testcontract::timestamp() {
    print(eosio::current_time_point().sec_since_epoch());
}
