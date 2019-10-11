# APKiD

[![Build Status](https://travis-ci.org/rednaga/APKiD.svg?branch=master)](https://travis-ci.org/rednaga/APKiD)
[![PyPI](https://img.shields.io/pypi/v/apkid.svg)](https://pypi.org/project/apkid/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/apkid.svg)](https://pypi.org/project/apkid/)
[![PyPI - Format](https://img.shields.io/pypi/format/apkid.svg)](https://pypi.org/project/apkid/)
[![PyPI - License](https://img.shields.io/pypi/l/apkid.svg)](https://pypi.org/project/apkid/)

APKiD gives you information about how an APK was made. It identifies many compilers, packers, obfuscators, and other weird stuff. It's [_PEiD_](https://www.aldeid.com/wiki/PEiD) for Android.

![Screen Shot 2019-05-07 at 10 55 00 AM](https://user-images.githubusercontent.com/1356658/57322793-49be9c00-70b9-11e9-84da-1e64d9459a8a.png)

For more information on what this tool can be used for, check out:

* [Android Compiler Fingerprinting](http://hitcon.org/2016/CMT/slide/day1-r0-e-1.pdf)
* [Detecting Pirated and Malicious Android Apps with APKiD](http://rednaga.io/2016/07/31/detecting_pirated_and_malicious_android_apps_with_apkid/)
* [APKiD: PEiD for Android Apps](https://github.com/enovella/cve-bio-enovella/blob/master/slides/bheu18-enovella-APKID.pdf)

# Installing

```bash

pip install --upgrade wheel
pip wheel --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.11.0
pip install --no-index --find-links=/tmp/yara-python yara-python
```

Finally, install APKiD:

```bash
pip install apkid
```

## Docker

You can also run APKiD with [Docker](https://www.docker.com/community-edition)! Of course, this requires that you have git and Docker installed.

Here's how to use Docker:

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD/
docker build . -t rednaga:apkid
docker/apkid.sh ~/reverse/targets/android/example/example.apk
[+] APKiD 2.1.0 :: from RedNaga :: rednaga.io
[*] example.apk!classes.dex
 |-> compiler : dx
```

# Usage

```
usage: apkid [-h] [-v] [-t TIMEOUT] [-r] [--scan-depth SCAN_DEPTH]
             [--entry-max-scan-size ENTRY_MAX_SCAN_SIZE] [--typing {magic,filename,none}] [-j]
             [-o DIR]
             [FILE [FILE ...]]

APKiD - Android Application Identifier v2.1.0

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
```

# Submitting New Packers / Compilers / Obfuscators

If you come across an APK or DEX which APKiD does not recognize, please open a GitHub issue and tell us:

* what you think it is -- obfuscated, packed, etc.
* the file hash (either MD5, SHA1, SHA256)

We are open to any type of concept you might have for "something interesting" to detect, so do not limit yourself solely to packers, compilers or obfuscators. If there is an interesting anti-disassembler, anti-vm, anti-* trick, please make an issue.

Pull requests are welcome. If you're submitting a new rule, be sure to include a file hash of the APK / DEX so we can check the rule.

# License

This tool is available under a dual license: a commercial one suitable for closed source projects and a GPL license that can be used in open source software.

Depending on your needs, you must choose one of them and follow its policies. A detail of the policies and agreements for each license type are available in the [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL) and [LICENSE.GPL](LICENSE.GPL) files.

# Hacking

If you want to install the latest version in order to make changes, develop your own rules, and so on, simply clone this repository, compile the rules, and install the package in editable mode:

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD
./prep-release.py
pip install -e .[dev,test]
```

If the above doesn't work, due to permission errors dependent on your local machine and where Python has been installed, try specifying the `--user` flag. This is likely needed if you're not using a virtual environment:

```bash
pip install -e .[dev,test] --user
```

If you update any of the rules, be sure to run `prep-release.py` to recompile them.

# For Maintainers

This section is for package maintainers.

To update the PyPI package:

```bash
./prep-release.py readme
rm -f dist/*
python setup.py sdist bdist_wheel
twine upload --repository-url https://upload.pypi.org/legacy/ dist/*
```

Update the generated `README.rst` until Pandoc learns how to translate Markdown with images that are links into reStructuredText:
```rst
.. image:: https://travis-ci.org/rednaga/APKiD.svg?branch=master
    :target: https://travis-ci.org/rednaga/APKiD

.. image:: https://img.shields.io/pypi/v/apkid.svg
    :target: https://pypi.python.org/pypi/apkid

.. image:: https://img.shields.io/pypi/pyversions/apkid.svg
    :target: https://pypi.python.org/pypi/apkid

.. image:: https://img.shields.io/pypi/format/apkid.svg
    :target: https://pypi.python.org/pypi/apkid

.. image:: https://img.shields.io/pypi/l/apkid.svg
    :target: https://pypi.python.org/pypi/apkid
```

For more information see [Packaging Projects](https://packaging.python.org/tutorials/packaging-projects/).
