# Mutation testing runner: nginx and the module built with clang and the
# Mull IR plugin, then the pytest suite run once per mutant by mull-runner.
#
# Mull packages exist for Debian 13 (trixie), hence a separate image from the
# Debian 12 test runner. They come from the GitHub release of Mull, pinned by
# version and SHA-256: the Cloudsmith apt repository of the project answers
# "402 Payment Required" since 2026-11.
FROM debian:trixie-slim

ARG LLVM=19
ARG MULL_VERSION=0.36.0
ARG MULL_LLVM_VERSION=19.1.7

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && arch=$(dpkg --print-architecture) \
    && case "${arch}" in \
        amd64) \
            mull_arch=amd64 \
            core_sha=c6e09d7d8e83b90efb996443ec221871e8cb81dc1fc448a85dda63d82bcd0a3c \
            plugin_sha=5b87c5e3287cd419f4d3bda61496380bc41df1301bfc71b57f0ca15213036770 ;; \
        arm64) \
            mull_arch=aarch64 \
            core_sha=42e2c50fd935c6da9d4beffdf0f9e074233be0cc4eeae261e75b4725439823f1 \
            plugin_sha=3045b36914b6586a0048873e75b75593bedb0e5e45a70e6da472df0ea7b5e09d ;; \
        *) echo "no Mull package for ${arch}" >&2; exit 1 ;; \
    esac \
    && base="https://github.com/mull-project/mull/releases/download/${MULL_VERSION}" \
    && core="Mull-${MULL_VERSION}-debian-${mull_arch}-13.deb" \
    && plugin="Mull-${LLVM}-${MULL_VERSION}-LLVM-${MULL_LLVM_VERSION}-debian-${mull_arch}-13.deb" \
    && curl -fsSL -o "/tmp/${core}" "${base}/${core}" \
    && curl -fsSL -o "/tmp/${plugin}" "${base}/${plugin}" \
    && echo "${core_sha}  /tmp/${core}" | sha256sum -c - \
    && echo "${plugin_sha}  /tmp/${plugin}" | sha256sum -c - \
    && apt-get install -y --no-install-recommends \
        "/tmp/${core}" \
        "/tmp/${plugin}" \
        "clang-${LLVM}" \
        "libclang-rt-${LLVM}-dev" \
        git \
        ldap-utils \
        libldap-dev \
        libpcre2-dev \
        libssl-dev \
        make \
        python3 \
        python3-pytest \
        python3-requests \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/*.deb

ENV PYTHONDONTWRITEBYTECODE=1 \
    LLVM=${LLVM}

COPY run-mutation.sh /usr/local/bin/run-mutation

ENTRYPOINT ["/bin/sh", "/usr/local/bin/run-mutation"]
