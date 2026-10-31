#!/bin/sh
# Build nginx with the module mounted at /src and run the pytest suite.
#
# Environment:
#   NGINX_VERSION  nginx release to build against (default: 1.30.6)
#   NGINX_DEBUG    1 to configure with --with-debug (debug-level error log)
#   SANITIZE       1 to build with AddressSanitizer
# Any arguments are passed to pytest unchanged.
set -eu

: "${NGINX_VERSION:=1.30.6}"
: "${NGINX_DEBUG:=0}"
: "${SANITIZE:=0}"

flavor="${NGINX_VERSION}-debug${NGINX_DEBUG}-asan${SANITIZE}"
build_dir="/build/nginx-${flavor}"
tarball="/build/nginx-${NGINX_VERSION}.tar.gz"

if [ ! -f "${build_dir}/objs/Makefile" ]; then
    if [ ! -f "${tarball}" ]; then
        echo "run-tests: downloading nginx ${NGINX_VERSION}"
        curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o "${tarball}.part"
        mv "${tarball}.part" "${tarball}"
    fi

    rm -rf "${build_dir}"
    mkdir -p "${build_dir}"
    tar -xzf "${tarball}" -C "${build_dir}" --strip-components=1

    cc_opt="-O1 -g -fno-omit-frame-pointer"
    ld_opt=""
    extra=""
    if [ "${SANITIZE}" = "1" ]; then
        cc_opt="${cc_opt} -fsanitize=address"
        ld_opt="-fsanitize=address"
    fi
    if [ "${NGINX_DEBUG}" = "1" ]; then
        extra="--with-debug"
    fi

    echo "run-tests: configuring nginx ${flavor}"
    (
        cd "${build_dir}"
        # shellcheck disable=SC2086 # $extra is intentionally word-split
        ./configure \
            --prefix=/tmp/nginx \
            --with-http_ssl_module \
            --with-http_v2_module \
            --with-cc-opt="${cc_opt}" \
            --with-ld-opt="${ld_opt}" \
            --add-module=/src \
            ${extra} >"${build_dir}/configure.log" 2>&1 \
            || { cat "${build_dir}/configure.log"; exit 1; }
    )
fi

# Incremental: only files changed under /src are recompiled.
echo "run-tests: building nginx ${flavor}"
make -C "${build_dir}" -j"$(nproc)" >"${build_dir}/make.log" 2>&1 \
    || { grep -E "error|warning" "${build_dir}/make.log" || tail -n 50 "${build_dir}/make.log"; exit 1; }

export NGINX_BINARY="${build_dir}/objs/nginx"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}"

"${NGINX_BINARY}" -V 2>&1 | head -n 1

cd /src/tests
exec python3 -m pytest "$@"
