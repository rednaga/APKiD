FROM python:3.11-slim
LABEL maintainer="RedNaga <rednaga@protonmail.com>"

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

WORKDIR /apkid
COPY . .

RUN python -m venv --copies /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

RUN python -m pip install yara-python-dex>=1.0.5 \
    && python prep-release.py \
    && python -m pip install .

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

RUN chown -R appuser:appuser /apkid && \
    chown -R appuser:appuser /input
USER appuser

ENTRYPOINT ["apkid"]
