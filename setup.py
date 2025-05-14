from setuptools import setup, find_packages

setup(
    name='noxrecon',
    version='2.0.0',
    packages=find_packages(),
    install_requires=[
        'colorama',
    ],
    entry_points={
        'console_scripts': [
            'noxrecon = noxrecon.menu:main_menu',
        ],
    },
    author='NoxRecon Team',
    description='Toolkit OSINT for Red Teaming',
    license='MIT',
)
