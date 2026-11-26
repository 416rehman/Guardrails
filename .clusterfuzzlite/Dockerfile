FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libssl-dev \
    pkg-config \
    protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*
COPY . $SRC/guardrails
WORKDIR $SRC/guardrails
