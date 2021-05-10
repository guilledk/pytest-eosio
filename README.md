To run tests:

1 - Install docker & python 3 (pyenv recommended)

2 - With ``python3`` installed, run:

    pip install -r requirements.txt
    pip install .

# Native mode:

###### (IMPORTANT: this plugin manages a local single block producer blockchain, this means it manages keosd & nodeos on its own, and requires them to not be running when executing tests)

3 - run tests:

    pytest --native

# Docker mode:

###### (IMPORTANT: Docker must be installed and running, ALSO: the first test session the plugin will download the docker image (452mb), so it might take a while)

3 - run tests:

    pytest


### Docker development commands

- docker build:
         
    docker build --tag guilledk/pytest-eosiocdt:  docker/

- docker push:

    docker push guilledk/pytest-eosiocdt:

- docker stop all:

    docker stop $(docker ps -q)

- docker clear:

    docker rmi $(docker images -a -q)
    docker rm $(docker ps -a -q)
