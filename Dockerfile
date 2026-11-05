FROM python:3.11-slim
LABEL maintainer="RedNaga <rednaga@protonmail.com>"

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

WORKDIR /apkid
COPY . .

RUN python -m venv --copies /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

# yara-x bindings come from the pinned yarax-python-dex wheel on PyPI
# (installed as a dependency of apkid); no Rust toolchain needed here.
RUN python -m pip install . \
    && python prep-release.py

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

RUN chown -R appuser:appuser /apkid && \
    chown -R appuser:appuser /input
USER appuser

ENTRYPOINT ["apkid"]
