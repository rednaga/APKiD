FROM python:3-slim
LABEL maintainer="RedNaga <rednaga@protonmail.com>"

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

RUN apt-get update -qq && \
    apt-get install -y git build-essential gcc pandoc curl

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip wheel --quiet --no-cache-dir --wheel-dir=/tmp/yara-python-dex git+https://github.com/MobSF/yara-python-dex.git && \
    pip install --quiet --no-cache-dir --no-index --find-links=/tmp/yara-python-dex yara-python-dex && \
    rm -rf /tmp/yara-python-dex

WORKDIR /apkid
COPY . .

RUN python prep-release.py && \
    pip install -e .

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

# Cleanup
RUN apt remove --purge -y \
        git \
        man \
        gcc && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/* > /dev/null 2>&1
    
RUN chown -R appuser:appuser /apkid && \
    chown -R appuser:appuser /input
USER appuser

ENTRYPOINT ["apkid"]
