from setuptools import setup, find_packages

setup(
    name='noxrecon',
    version='1.0.0',
    description='NoxRecon - OSINT Reconnaissance Toolkit for Pentesters',
    author='Issman',
    author_email='ismaeldevs@gmail.com',
    url='https://github.com/Ismaeldevs/NoxRecon',
    packages=find_packages(),
    install_requires=[],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Information Technology',
        'Operating System :: OS Independent',
        'Topic :: Security',
    ],
    entry_points={
        'console_scripts': [
            'noxrecon=noxrecon.cli:main',
        ],
    },
    python_requires='>=3.6',
)
