# Test runner: toolchain to build nginx with the module, plus pytest.
#
# nginx itself is downloaded and built by run-tests.sh at container start and
# cached in the /build volume, so switching NGINX_VERSION needs no image
# rebuild and editing the module only recompiles the module object.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        gcovr \
        ldap-utils \
        libldap2-dev \
        libpcre2-dev \
        libssl-dev \
        python3 \
        python3-pytest \
        python3-requests \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1

COPY run-tests.sh /usr/local/bin/run-tests

ENTRYPOINT ["/bin/sh", "/usr/local/bin/run-tests"]
