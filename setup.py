from distutils.core import setup

setup(
	name='pytest-eosiocdt',
	version='0.1.0-indev',
	description='Pytest plugin for smart contract development',
	author='Guillermo Rodriguez',
	author_email='guillermor@fing.edu.uy',
	packages=['pytest_eosiocdt'],
	entry_points={"pytest11": ["pytest-eosiocdt = pytest_eosiocdt.plugin"]},
	classifiers=["Framework :: Pytest"],
	install_requires=[
		'pytest',
		'psutil',
		'pytest-dockerctl@git+git://github.com/tgoodlet/pytest-dockerctl.git'
	]
)