from setuptools import setup

setup(
    name = 'PyXiaomiGateway',
    packages = ['PyXiaomiGateway'],
    install_requires=['pyserial>=2.7'],
    version = '0.1.0',
    description = 'a library to communicate with the Xiaomi Gateway',
    author='Daniel Høyer Iversen',

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
