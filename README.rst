APKiD
=====

APKiD gives you information about how an APK was made. It identifies
many compilers, packers, obfuscators, and other weird stuff. **It's PEiD
for Android.**

Knowing the compiler can be a *strong* signal that an app is malicious
or pirated. This is because there are certain tools which produce APKs
which are almost never used by the original legitimate developer

Installing
==========

.. code:: bash

    git clone https://github.com/rednaga/yara-python
    cd yara-python
    python setup.py install
    pip install apkid

The *yara-python* dependency is temporarily necessary to install our
custom DEX Yara module. We're working on removing this.

Usage
=====

::

    usage: apkid [-h] FILE [FILE ...]

    Android Application Identifier

    positional arguments:
      FILE        apk, dex, or dir

    optional arguments:
      -h, --help  show this help message and exit

Submitting New Packers
======================

If you come across an APK or DEX that apkid does not recognize, please
open a GitHub issue and tell us what you think it is and provide the
file hash (either MD5, SHA1, SHA256).

Licensing
=========

This tool is available under a dual license: a a commercial one suitable
for closed source projects and a GPL license that can be used in open
source software.

Depending on your needs, you must choose one of them and follow its
policies. A detail of the policies and agreements for each license type
are available in the LICENSE.COMMERCIAL and LICENSE.GPL files.

Hacking
=======

To install the package from source in editable mode (useful for
devlopment):

.. code:: bash

    pip install -e .

If the above doesn't work, due to permission errors dependant on your
local machine and where Python has been installed, try specifying the
``--user`` flag. This is likely needed if you are working on OSX:

.. code:: bash

    pip install -e . --user
