from distutils.core import setup

setup(
	name='pytest-eosiocdt',
	version='0.1a3',
	description='Pytest plugin for smart contract development',
	author='Guillermo Rodriguez',
	author_email='guillermor@fing.edu.uy',
	packages=['pytest_eosiocdt'],
	entry_points={"pytest11": ["pytest-eosiocdt = pytest_eosiocdt.plugin"]},
	classifiers=["Framework :: Pytest"],
	install_requires=[
        'six',  # docker,
        'toml',
		'pytest',
		'psutil',
        'natsort',
        'requests',
		'pytest-dockerctl@git+git://github.com/pikers/pytest-dockerctl.git'
	]
)
