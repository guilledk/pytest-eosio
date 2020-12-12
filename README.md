To run tests:

1 - Install docker & python 3 (pyenv recommended)

2 - With ``python3`` installed, run:

	pip install -r requirements.txt
	pip install .

# Native mode:

(IMPORTANT: this plugin manages a local single block producer blockchain, this means it manages keosd & nodeos on its own, and requires them to not be running when executing tests)

3 - run tests:

	pytest --native

# Docker mode:

(Docker must be installed and running)

3 - Build docker image from folder:

	docker build --tag vtestnet:eosio \
	    --build-arg USER_ID=$(id -u) \
	    --build-arg GROUP_ID=$(id -g) docker/vtestnet-eosio

4 - run tests:

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