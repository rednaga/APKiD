FROM python:3.11-slim
LABEL maintainer="RedNaga <rednaga@protonmail.com>"

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

WORKDIR /apkid
COPY . .

RUN python -m venv --copies /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends curl gcc pkg-config make \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
    && export PATH="$HOME/.cargo/bin:$PATH" \
    && python -m pip install maturin \
    && cd yarax_patches && make patch && cd yara-x/py \
    && maturin build --release --no-default-features \
        --features dex-module,elf-module,pe-module,hash-module \
    && python -m pip install /apkid/yarax_patches/yara-x/target/wheels/yara_x-*.whl \
    && cd /apkid && python prep-release.py \
    && python -m pip install .

# Place to bind a mount point to for scratch pad work
RUN mkdir /input
WORKDIR /input

RUN chown -R appuser:appuser /apkid && \
    chown -R appuser:appuser /input
USER appuser

ENTRYPOINT ["apkid"]
