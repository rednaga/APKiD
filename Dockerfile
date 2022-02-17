# Python 3.10 fails to install a simple PyPi dependency with setup.py
FROM python:3.9-slim
LABEL maintainer="RedNaga <rednaga@protonmail.com>"

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

WORKDIR /apkid
COPY . .

RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python setup.py install \
    && python prep-release.py \
    && pip install -e .

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

RUN chown -R appuser:appuser /apkid && \
    chown -R appuser:appuser /input
USER appuser

ENTRYPOINT ["apkid"]
