from setuptools import setup, find_packages
import sys, os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()


version = '0.1'

install_requires = [
    # http://python-packaging.readthedocs.io/en/latest/dependencies.html
    'yara',
]


setup(name='apkid',
    version=version,
    description="Android Package Identifier",
    long_description=README,
    classifiers=[
      # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      'Development Status :: 4 - Beta',
      'Environment :: Console',
      'Intended Audience :: Science/Research',
      'License :: OSI Approved :: Apache Software License',
      'Natural Language :: English',
      'Programming Language :: Python :: 2.7',
      'Topic :: Security',
      'Topic :: Utilities',
    ],
    keywords='android analysis reversing malware dex',
    author='RedNaga',
    author_email='rednaga@protonmail.com',
    url='rednaga.io',
    license='Apache License 2.0',
    packages=find_packages('src'),
    package_dir = {'': 'src',},include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    entry_points={
        'console_scripts':
            ['apkid=apkid:main']
    }
)
