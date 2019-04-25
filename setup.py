from setuptools import setup

setup(
    name = 'PyXiaomiGateway',
    packages = ['xiaomi_gateway'],
    install_requires=['cryptography>=2.1.1'],
    version = '0.12.3',
    description = 'A library to communicate with the Xiaomi Gateway',
    author='Daniel Hoyer Iversen',
    url='https://github.com/Danielhiversen/PyXiaomiGateway/',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Home Automation',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ]
)
