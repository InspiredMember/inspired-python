
from setuptools import setup, find_packages
from insprd.core.version import get_version

VERSION = get_version()

f = open('README.md', 'r')
LONG_DESCRIPTION = f.read()
f.close()

setup(
    name='insprd',
    version=VERSION,
    description='Python interface to Inspired Platform',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author='Jeff Trudeau',
    author_email='jeff.trudeau@gmail.com',
    url='https://github.com/InspiredMember/inspired-python',
    license='MIT',
    packages=find_packages(exclude=['ez_setup', 'tests*']),
    package_data={'insprd': ['templates/*']},
    include_package_data=True,
    entry_points="""
        [console_scripts]
        insprd = insprd.main:main
    """,
)
