from setuptools import setup

setup(
    name='ntp2chrony',
    version=0.1,
    packages=['ntp2chrony'],
    entry_points='''
        [console_scripts]
        ntp2chrony=ntp2chronyconverter.ntp2chrony:main
    '''
)
