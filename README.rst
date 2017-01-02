APKiD
=====

APKiD gives you information about how an APK was made. It identifies
many compilers, packers, obfuscators, and other weird stuff. It's *PEiD*
for Android.

For more information on what this tool can be used for, check out:

-  `Android Compiler
   Fingerprinting <http://hitcon.org/2016/CMT/slide/day1-r0-e-1.pdf>`__
-  `Detecting Pirated and Malicious Android Apps with
   APKiD <http://rednaga.io/2016/07/31/detecting_pirated_and_malicious_android_apps_with_apkid/>`__

Installing
==========

The *yara-python* clone and compile steps here are temporarily necessary
because we must point directly to our modified version of a *Yara*
branch which includes our DEX Yara module. This step is nessecary until
(if?) the original maintainers of *Yara* merge our module into the
master branch. When this happens, we will undate the instructions here.
After the *yara-python* fork is compiled, you can use ``pip`` to the
most currently published ``APKiD`` package.

.. code:: bash

    git clone https://github.com/rednaga/yara-python
    cd yara-python
    python setup.py install
    pip install apkid

Usage
=====

::

    usage: apkid [-h] [-j] [-t TIMEOUT] [-o DIR] [FILE [FILE ...]]

    APKiD - Android Application Identifier v0.9.5

    positional arguments:
      FILE                  apk, dex, or directory

    optional arguments:
      -h, --help            show this help message and exit
      -j, --json            output results in JSON format
      -t TIMEOUT, --timeout TIMEOUT
                            Yara scan timeout (in seconds)
      -o DIR, --output-dir DIR
                            write individual JSON results to this directory

Submitting New Packers / Compilers / Obfuscators
================================================

If you come across an APK or DEX that APKiD does not recognize, please
open a GitHub issue and tell us: \* what you think it is \* the file
hash (either MD5, SHA1, SHA256)

We are open to any type of concept you might have for "something
interesting" to detect, so do not limit yourself solely to packers,
compilers or obfuscators. If there is an interesting anti disassembler,
anti vm, anti\* trick, please make an issue.

You're also welcome to submit pull requests. Just be sure to include a
file hash so we can check the rule.

License
=======

This tool is available under a dual license: a commercial one suitable
for closed source projects and a GPL license that can be used in open
source software.

Depending on your needs, you must choose one of them and follow its
policies. A detail of the policies and agreements for each license type
are available in the LICENSE.COMMERCIAL and LICENSE.GPL files.

Hacking
=======

First you will need to install the specific version of *yara-python* the
project depends on (more information about this in the *Installing*
section):

.. code:: bash

    git clone https://github.com/rednaga/yara-python
    cd yara-python
    python setup.py install

Then, clone this repo, compile the rules, and install the package in
editable mode:

.. code:: bash

    git clone https://github.com/rednaga/APKiD
    cd APKiD
    pip install -e .[dev]
    ./prep-release.py

If the above doesn't work, due to permission errors dependent on your
local machine and where Python has been installed, try specifying the
``--user`` flag. This is likely needed if you are working on OSX:

.. code:: bash

    pip install -e .[dev] --user
