FROM python:3-slim

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

RUN apt-get update -qq && \
    apt-get install -y git build-essential gcc pandoc
RUN pip install --upgrade pip setuptools wheel


RUN pip wheel --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.11.0 && \
    pip install --no-index --find-links=/tmp/yara-python yara-python && \
    rm -rf /tmp/yara-python

RUN apt-get install -y curl

WORKDIR /apkid
COPY . .

RUN python prep-release.py && \
    pip install -e .

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

RUN chown -R appuser:appuser /apkid
RUN chown -R appuser:appuser /input
USER appuser

ENTRYPOINT ["apkid"]
