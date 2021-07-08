To run tests:

1 - Install docker & python 3 (pyenv recommended)

2 - With ``python3`` installed, run:

    pip install -r requirements.txt
    pip install .

###### (IMPORTANT: Docker must be installed and running)

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
