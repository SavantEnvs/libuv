# Mayhem fuzzing Dockerfile for mayhemheroes/libuv
# Fuzzes IDNA hostname parsing, UTF-8 decoding, and IP address parsing APIs.
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    cmake \
    make \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src/libuv

# Build libuv as a static library
RUN cmake -S /src/libuv -B /build \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_BUILD_TYPE=Release \
        -DLIBUV_BUILD_SHARED=OFF \
        -DLIBUV_BUILD_TESTS=OFF \
        -DLIBUV_BUILD_BENCH=OFF \
        -DCMAKE_C_FLAGS="-gdwarf-4 -fno-omit-frame-pointer" \
    && cmake --build /build --target uv_a -j$(nproc)

# Build the fuzzer binary
RUN clang \
        -fsanitize=fuzzer,address \
        -gdwarf-4 \
        -fno-omit-frame-pointer \
        -I/src/libuv/include \
        -I/src/libuv/src \
        /src/libuv/fuzz/fuzz_idna.c \
        /build/libuv.a \
        -lpthread \
        -o /fuzz_idna

# ── final stage ──────────────────────────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libasan6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /fuzz_idna /fuzz_idna

# Mayhem expects the fuzzer as the entrypoint
ENTRYPOINT ["/fuzz_idna"]
