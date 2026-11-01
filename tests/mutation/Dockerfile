# Mutation testing runner: nginx and the module built with clang and the
# Mull IR plugin, then the pytest suite run once per mutant by mull-runner.
#
# Mull packages exist for Debian 13 (trixie), hence a separate image from the
# Debian 12 test runner.
FROM debian:trixie-slim

ARG LLVM=19

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        curl \
        debian-keyring \
        gnupg \
    && curl -1sLf 'https://dl.cloudsmith.io/public/mull-project/mull-stable/setup.deb.sh' | bash \
    && apt-get install -y --no-install-recommends \
        "clang-${LLVM}" \
        "libclang-rt-${LLVM}-dev" \
        git \
        ldap-utils \
        libldap-dev \
        libpcre2-dev \
        libssl-dev \
        make \
        "mull-${LLVM}" \
        python3 \
        python3-pytest \
        python3-requests \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    LLVM=${LLVM}

COPY run-mutation.sh /usr/local/bin/run-mutation

ENTRYPOINT ["/bin/sh", "/usr/local/bin/run-mutation"]
