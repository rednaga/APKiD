#!/usr/bin/env python
from setuptools import setup, find_packages
from codecs import open
from os import path, walk

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
  long_description = f.read()

def package_files(directory):
  paths = []
  for (filepath, directories, filenames) in walk(directory):
    for filename in filenames:
      paths.append(path.join('..', filepath , filename))
  return paths


version = '0.9.0'
install_requires = [
  'yara-python-rednaga==3.4.0',
]

setup(
  name='apkid',

  version=version,

  description="Android Package Identifier",
  long_description=long_description,

  url='https://github.com/rednaga/APKiD',

  author='RedNaga',
  author_email='rednaga@protonmail.com',

  license='Apache License 2.0',

  classifiers=[
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Intended Audience :: Science/Research',
    'License :: OSI Approved :: Apache Software License',
    'Natural Language :: English',
    'Programming Language :: Python :: 2.7',
    'Topic :: Security',
    'Topic :: Utilities',
  ],

  keywords='android analysis reversing malware apk dex',

  packages=find_packages('src', exclude=['docs', 'tests']),
  install_requires=install_requires,
  dependency_links = [
    'https://github.com/rednaga/yara-python/zipball/master#egg=yara-python-rednaga-3.4.0'
  ],
  extras_require={
    'dev': ['pypandoc'],
    'test': [],
  },

  package_data={
    'rules': package_files('apkid/rules/'),
  },

  zip_safe=False,
  entry_points={
    'console_scripts': [
      'apkid=apkid:main',
    ],
  },
)
