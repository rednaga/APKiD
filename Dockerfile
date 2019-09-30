FROM python:3-slim

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

RUN apt-get update -qq && \
    apt-get install -y git build-essential gcc pandoc
RUN pip install --upgrade pip setuptools wheel

# Disabled until Yara patch is applied
#RUN pip wheel --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.10.0
#RUN pip install --no-index --find-links=/tmp/yara-python yara-python
#RUN rm -rf /tmp/yara-python

RUN apt-get install -y curl
RUN git clone --recursive -b "v3.10.0" https://github.com/VirusTotal/yara-python.git /tmp/yara-python
RUN git config --global user.email "apkid@user.com"
RUN git config --global user.name "APKiD User"
WORKDIR /tmp/yara-python
RUN cd yara && \
    curl https://patch-diff.githubusercontent.com/raw/VirusTotal/yara/pull/1073.patch | git am
RUN cd /tmp/yara-python
RUN python setup.py build --enable-dex
RUN python setup.py install

WORKDIR /apkid
COPY . .

RUN python prep-release.py
RUN pip install -e .

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

RUN chown -R appuser:appuser /apkid
RUN chown -R appuser:appuser /input
USER appuser

ENTRYPOINT ["apkid"]
