# APKiD

[![Build Status](https://travis-ci.org/rednaga/APKiD.svg?branch=master)](https://travis-ci.org/rednaga/APKiD)

APKiD gives you information about how an APK was made. It identifies many compilers, packers, obfuscators, and other weird stuff. It's _PEiD_ for Android.

For more information on what this tool can be used for check out:

* [Android Compiler Fingerprinting](http://hitcon.org/2016/CMT/slide/day1-r0-e-1.pdf)
* [Detecting Pirated and Malicious Android Apps with APKiD](http://rednaga.io/2016/07/31/detecting_pirated_and_malicious_android_apps_with_apkid/)

# Installing

Unfortunately, you can't just `pip install` APKiD since it depends on RedNaga's custom fork of [yara-python](https://github.com/rednaga/yara-python-1).

First, install our yara-python fork:

```bash
git clone --recursive https://github.com/rednaga/yara-python-1 yara-python
cd yara-python
python setup.py build --enable-dex install
```

Then, you can install apkid normally:
```bash
pip install apkid
```

This extra step is necessary until yara-python is updated with a version of Yara which includes the new, experimental DEX module.

## Docker

If installing is too complicated, you can just use [Docker](https://www.docker.com/community-edition)! Of course, this usage requires that you have git and docker installed on your machine.

Here's how to use Docker:

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD/
docker build . -t rednaga:apkid
docker/apkid.sh ~/reverse/targets/android/example/example.apk
[+] APKiD 1.2.1 :: from RedNaga :: rednaga.io
[*] example.apk!classes.dex
 |-> compiler : dx
```

# Usage

```
usage: apkid [-h] [-j] [-t TIMEOUT] [-o DIR] [-q] [FILE [FILE ...]]

APKiD - Android Application Identifier v1.2.1

positional arguments:
  FILE                           apk, dex, or directory

optional arguments:
  -h, --help                     show this help message and exit
  -j, --json                     output scan results in JSON format
  -t TIMEOUT, --timeout TIMEOUT  Yara scan timeout (in seconds)
  -o DIR, --output-dir DIR       write individual results to this directory (implies --json)
  -q, --quiet                    suppress extraneous output
```

# Submitting New Packers / Compilers / Obfuscators

If you come across an APK or DEX which APKiD does not recognize, please open a GitHub issue and tell us:

* what you think it is
* the file hash (either MD5, SHA1, SHA256)

We are open to any type of concept you might have for "something interesting" to detect, so do not limit yourself solely to packers, compilers or obfuscators. If there is an interesting anti-disassembler, anti-vm, anti-* trick, please make an issue.

Pull requests are welcome. If you're submitting a new rule, be sure to include a file hash of the APK / DEX so we can check the rule.

# License

This tool is available under a dual license: a commercial one suitable for closed source projects and a GPL license that can be used in open source software.

Depending on your needs, you must choose one of them and follow its policies. A detail of the policies and agreements for each license type are available in the LICENSE.COMMERCIAL and LICENSE.GPL files.

# Hacking

First, you'll need to install our fork of _yara-python_:

```bash
git clone --recursive https://github.com/rednaga/yara-python-1 yara-python
cd yara-python
python setup.py build --enable-dex install
```

Then, clone this repository, compile the rules, and install the package in editable mode:

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD
./prep-release.py
pip install -e .[dev]
```

If the above doesn't work, due to permission errors dependent on your local machine and where Python has been installed, try specifying the `--user` flag. This is likely needed if you are working on OSX:

```bash
pip install -e .[dev] --user
```

If you update any of the rules, be sure to run `prep-release.py` to recompile them.

# For Maintainers

This section is for package maintainers.

To update the PyPI package:

```bash
./prep-release.py readme
rm dist/*
python setup.py sdist bdist_wheel
twine upload --repository-url https://upload.pypi.org/legacy/ dist/*
```

For more information see [Packaging Projects](https://packaging.python.org/tutorials/packaging-projects/).
