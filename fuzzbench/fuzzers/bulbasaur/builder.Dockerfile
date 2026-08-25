# Copyright 2026 Bulbasaur contributors
#
# The source tree is deliberately cloned during image build. FuzzBench users
# can override both arguments for a fork or a pinned release.

ARG parent_image
FROM $parent_image

ARG BULBASAUR_REPO_URL=https://github.com/vul337/Bulbasaur.git
ARG BULBASAUR_REF=main

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential ca-certificates clang curl git llvm llvm-dev python3 \
    python3-venv && rm -rf /var/lib/apt/lists/*

RUN if command -v rustc >/dev/null 2>&1; then rustc --version; else \
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /rustup.sh && \
      sh /rustup.sh --default-toolchain stable -y && rm /rustup.sh; fi

RUN git clone --depth 1 --branch "${BULBASAUR_REF}" \
      "${BULBASAUR_REPO_URL}" /Bulbasaur
RUN cd /Bulbasaur && PATH="/root/.cargo/bin:${PATH}" cargo build --release
RUN cd /Bulbasaur/afl_llvm_mode && make BULBASAUR_PLUGIN_STDLIB=-stdlib=libstdc++ -j"$(nproc)" \
      afl-cc afl-compiler-rt.o bulbasaur-cov-full.so \
      bulbasaur-cov-fast.so bulbasaur-cov-trace.so bulbasaur-cov-debug.so \
      cmplog-routines-pass.so afl-llvm-dict2file.so && make -C aflpp_driver

# Keep the driver archive separate from afl-compiler-rt.o. afl-cc injects the
# runtime for every instrumented link; removing an inherited archive first is
# important because `ar cr` otherwise preserves stale members.
RUN cp /Bulbasaur/afl_llvm_mode/libAFLDriver.a /libAFLDriver.a && \
    rm -f /libBulbasaurFuzzingEngine.a && \
    ar cr /libBulbasaurFuzzingEngine.a \
      /Bulbasaur/afl_llvm_mode/aflpp_driver/aflpp_driver.o
