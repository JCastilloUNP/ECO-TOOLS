from setuptools import setup, find_packages
from eco_tools import __version__

setup(
    name='eco-tools',
    version=__version__,
    description='Librería con set de herramientas para las aplicaciones de ecosistema',
    url='',
    author='GCCIprotUNP',
    author_email='gcciprot@unp.gov.co',
    packages=find_packages(),
    install_requires=[
        'django-rest-framework',
        'jwcrypto'
    ],
)