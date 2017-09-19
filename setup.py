from setuptools import setup

setup(
    name = 'PyXiaomiGateway',
    packages = ['PyXiaomiGateway'],
    install_requires=['pyCrypto==2.6.1'],
    version = '0.4.2',
    description = 'a library to communicate with the Xiaomi Gateway',
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
