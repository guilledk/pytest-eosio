To run tests:

1 - Install docker & python 3 (pyenv recommended)

2 - With ``python3`` installed, run:

	pip install -r requirements.txt
	pip install .

# Native mode:

3 - Run keos & nodeos

	keosd &

	nodeos -e -p eosio \
          --plugin eosio::producer_plugin \
          --plugin eosio::producer_api_plugin \
          --plugin eosio::chain_api_plugin \
          --plugin eosio::http_plugin \
          --plugin eosio::history_plugin \
          --plugin eosio::history_api_plugin \
          --filter-on="*" \
          --access-control-allow-origin='*' \
          --contracts-console \
          --http-validate-host=false \
          --verbose-http-errors >> /tmp/nodeos.log 2>&1 &

4 - run tests:

	pytest --native

# Docker mode:

3 - Build docker image from folder:

	docker build --tag vtestnet:eosio \
	    --build-arg USER_ID=$(id -u) \
	    --build-arg GROUP_ID=$(id -g) docker/vtestnet-eosio

4 - Start docker

	systemctl start docker

5 - run tests:

	pytest


docker build interactive:

	docker build --tag vtestnet:eosio-inter \
	    --build-arg USER_ID=$(id -u) \
	    --build-arg GROUP_ID=$(id -g) docker/vtestnet-eosio.interactive


docker run interactive:

	docker run -it --mount type=bind,source="$(pwd)"/contracts,target=/contracts \
		vtestnet:eosio-inter bash

docker clear:

	docker rmi $(docker images -a -q)s
	docker rm $(docker ps -a -q)