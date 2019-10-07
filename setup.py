from setuptools import find_packages, setup

from insprd import version
from insprd.utils.version import get_version


VERSION = get_version(version)

with open('README.md', 'r') as f:
    LONG_DESCRIPTION = f.read()


setup(
    name='insprd',
    version=VERSION,
    description='Python interface into Inspired Platform',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author='Jeff Trudeau',
    author_email='jeff.trudeau@gmail.com',
    url='https://github.com/InspiredMember/inspired-python',
    license='MIT',
    packages=find_packages(exclude=['ez_setup', 'tests*']),
    package_data={'insprd': ['templates/*']},
    include_package_data=True,
    install_requires=[
        'cryptography==2.7',
        'PyJWT==1.7.1',
        'requests==2.22.0',
    ],
    python_requires='>=3.6',
    entry_points="""
    """,
)
