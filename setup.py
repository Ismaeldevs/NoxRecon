from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name='noxrecon',
    version='2.0.0',
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'noxrecon = noxrecon.menu:main_menu',
        ],
    },
    author='NoxRecon Team',
    author_email='contact@noxrecon.dev',
    description='Advanced OSINT Toolkit for Red Teaming and Penetration Testing',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Ismaeldevs/NoxRecon',
    project_urls={
        'Bug Reports': 'https://github.com/Ismaeldevs/NoxRecon/issues',
        'Source': 'https://github.com/Ismaeldevs/NoxRecon',
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
    ],
    python_requires='>=3.8',
    license='MIT',
    keywords='osint, reconnaissance, pentesting, cybersecurity, red-team',
)
