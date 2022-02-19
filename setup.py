from distutils.core import setup

setup(
	name='pytest-eosio',
	version='0.1a7',
	description='Pytest plugin for smart contract development',
	author='Guillermo Rodriguez',
	author_email='guillermor@fing.edu.uy',
	packages=['pytest_eosio'],
	entry_points={"pytest11": ["pytest-eosio = pytest_eosio.plugin"]},
	classifiers=["Framework :: Pytest"],
	install_requires=[
        'six',  # docker,
        'toml',
		'pytest',
		'psutil',
        'natsort',
        'requests',
		'pytest-dockerctl@git+git://github.com/guilledk/pytest-dockerctl.git@host_network'
	]
)
