APKiD
=====

|Build Status| |PyPI| |PyPI - Python Version| |PyPI - Format| |PyPI -
License|

APKiD gives you information about how an APK was made. It identifies
many compilers, packers, obfuscators, and other weird stuff. It’s
`PEiD <https://www.aldeid.com/wiki/PEiD>`__ for Android.

.. figure:: https://user-images.githubusercontent.com/1356658/57322793-49be9c00-70b9-11e9-84da-1e64d9459a8a.png
   :alt: Screen Shot 2019-05-07 at 10 55 00 AM

   Screen Shot 2019-05-07 at 10 55 00 AM

For more information on what this tool can be used for, check out:

-  `Android Compiler
   Fingerprinting <http://hitcon.org/2016/CMT/slide/day1-r0-e-1.pdf>`__
-  `Detecting Pirated and Malicious Android Apps with
   APKiD <http://rednaga.io/2016/07/31/detecting_pirated_and_malicious_android_apps_with_apkid/>`__
-  `APKiD: PEiD for Android
   Apps <https://github.com/enovella/cve-bio-enovella/blob/master/slides/bheu18-enovella-APKID.pdf>`__

Installing
----------

.. code:: bash

   pip install apkid

Docker
~~~~~~

You can also run APKiD with
`Docker <https://www.docker.com/community-edition>`__! Of course, this
requires that you have git and Docker installed.

Here’s how to use Docker:

.. code:: bash

   git clone https://github.com/rednaga/APKiD
   cd APKiD/
   docker build . -t rednaga:apkid
   docker/apkid.sh ~/reverse/targets/android/example/example.apk
   [+] APKiD 2.1.0 :: from RedNaga :: rednaga.io
   [*] example.apk!classes.dex
    |-> compiler : dx

Usage
-----

::

   usage: apkid [-h] [-v] [-t TIMEOUT] [-r] [--scan-depth SCAN_DEPTH]
                [--entry-max-scan-size ENTRY_MAX_SCAN_SIZE] [--typing {magic,filename,none}] [-j]
                [-o DIR]
                [FILE [FILE ...]]

   APKiD - Android Application Identifier v2.1.2

   positional arguments:
     FILE                                       apk, dex, or directory

   optional arguments:
     -h, --help                                 show this help message and exit
     -v, --verbose                              log debug messages

   scanning:
     -t TIMEOUT, --timeout TIMEOUT              Yara scan timeout (in seconds)
     -r, --recursive                            recurse into subdirectories
     --scan-depth SCAN_DEPTH                    how deep to go when scanning nested zips
     --entry-max-scan-size ENTRY_MAX_SCAN_SIZE  max zip entry size to scan in bytes, 0 = no limit
     --typing {magic,filename,none}             method to decide which files to scan

   output:
     -j, --json                                 output scan results in JSON format
     -o DIR, --output-dir DIR                   write individual results here (implies --json)

Submitting New Packers / Compilers / Obfuscators
------------------------------------------------

If you come across an APK or DEX which APKiD does not recognize, please
open a GitHub issue and tell us:

-  what you think it is – obfuscated, packed, etc.
-  the file hash (either MD5, SHA1, SHA256)

We are open to any type of concept you might have for “something
interesting” to detect, so do not limit yourself solely to packers,
compilers or obfuscators. If there is an interesting anti-disassembler,
anti-vm, anti-\* trick, please make an issue.

Pull requests are welcome. If you’re submitting a new rule, be sure to
include a file hash of the APK / DEX so we can check the rule.

License
-------

This tool is available under a dual license: a commercial one suitable
for closed source projects and a GPL license that can be used in open
source software.

Depending on your needs, you must choose one of them and follow its
policies. A detail of the policies and agreements for each license type
are available in the `LICENSE.COMMERCIAL <LICENSE.COMMERCIAL>`__ and
`LICENSE.GPL <LICENSE.GPL>`__ files.

Hacking
-------

If you want to install the latest version in order to make changes,
develop your own rules, and so on, simply clone this repository, compile
the rules, and install the package in editable mode:

.. code:: bash

   git clone https://github.com/rednaga/APKiD
   cd APKiD
   ./prep-release.py
   pip install -e .[dev,test]

If the above doesn’t work, due to permission errors dependent on your
local machine and where Python has been installed, try specifying the
``--user`` flag. This is likely needed if you’re not using a virtual
environment:

.. code:: bash

   pip install -e .[dev,test] --user

If you update any of the rules, be sure to run ``prep-release.py`` to
recompile them.

For Maintainers
---------------

This section is for package maintainers.

Make sure the version has been updated in
`apkid/init.py <apkid/__init__.py>`__

Update the compiled rules, the readme, build the package and upload to
PyPI:

.. code:: bash

   ./prep-release.py readme
   rm -f dist/*
   python setup.py sdist bdist_wheel
   twine upload --repository-url https://upload.pypi.org/legacy/ dist/*

For more information see `Packaging
Projects <https://packaging.python.org/tutorials/packaging-projects/>`__.

.. |Build Status| image:: https://travis-ci.org/rednaga/APKiD.svg?branch=master
   :target: https://travis-ci.org/rednaga/APKiD
.. |PyPI| image:: https://img.shields.io/pypi/v/apkid.svg
   :target: https://pypi.org/project/apkid/
.. |PyPI - Python Version| image:: https://img.shields.io/pypi/pyversions/apkid.svg
   :target: https://pypi.org/project/apkid/
.. |PyPI - Format| image:: https://img.shields.io/pypi/format/apkid.svg
   :target: https://pypi.org/project/apkid/
.. |PyPI - License| image:: https://img.shields.io/pypi/l/apkid.svg
   :target: https://pypi.org/project/apkid/
