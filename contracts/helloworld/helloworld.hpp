#include <eosio/eosio.hpp>
using namespace eosio;

class [[eosio::contract]] helloworld : public contract {
   public:
      using contract::contract;

      [[eosio::action]]
      void hi( name nm );

      using hi_action = action_wrapper<"hi"_n, &helloworld::hi>;
};
