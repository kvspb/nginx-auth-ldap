#!/bin/sh
# Build nginx with the module mounted at /src and run the pytest suite.
#
# Environment:
#   NGINX_VERSION  nginx release to build against (default: 1.30.6)
#   NGINX_DEBUG    1 to configure with --with-debug (debug-level error log)
#   SANITIZE       1 to build with AddressSanitizer
#   COVERAGE       1 to build with gcov instrumentation and write a coverage
#                  report of the module sources to /reports/coverage
# Any arguments are passed to pytest unchanged.
set -eu

: "${NGINX_VERSION:=1.30.6}"
: "${NGINX_DEBUG:=0}"
: "${SANITIZE:=0}"
: "${COVERAGE:=0}"

flavor="${NGINX_VERSION}-debug${NGINX_DEBUG}-asan${SANITIZE}-cov${COVERAGE}"
build_dir="/build/nginx-${flavor}"
tarball="/build/nginx-${NGINX_VERSION}.tar.gz"

# nginx bakes the module's source list into objs/Makefile at configure time,
# so a changed ./config (e.g. files added or moved) needs a fresh configure.
config_sum=$(sha256sum /src/config | cut -d' ' -f1)
if [ -f "${build_dir}/objs/Makefile" ] \
    && [ "$(cat "${build_dir}/.module-config" 2>/dev/null)" != "${config_sum}" ]; then
    echo "run-tests: module config changed, reconfiguring"
    rm -f "${build_dir}/objs/Makefile"
fi

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
    if [ "${COVERAGE}" = "1" ]; then
        # -O0 keeps line counts faithful to the source.
        cc_opt="${cc_opt} -O0 --coverage"
        ld_opt="${ld_opt} --coverage"
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
    echo "${config_sum}" >"${build_dir}/.module-config"
fi

# Incremental: only files changed under /src are recompiled.
echo "run-tests: building nginx ${flavor}"
make -C "${build_dir}" -j"$(nproc)" >"${build_dir}/make.log" 2>&1 \
    || { grep -E "error|warning" "${build_dir}/make.log" || tail -n 50 "${build_dir}/make.log"; exit 1; }

export NGINX_BINARY="${build_dir}/objs/nginx"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}"

"${NGINX_BINARY}" -V 2>&1 | head -n 1

cd /src/tests

if [ "${COVERAGE}" != "1" ]; then
    exec python3 -m pytest "$@"
fi

# Counters from earlier runs would inflate the report.
find "${build_dir}/objs" -name '*.gcda' -delete

status=0
python3 -m pytest "$@" || status=$?

# Workers flush their counters when they exit normally; a crashed worker
# (signal) loses the counts of its last requests.
report_dir=/reports/coverage
rm -rf "${report_dir}"
mkdir -p "${report_dir}"
# gcov resolves source paths relative to the compiler's working directory,
# which is the nginx build directory; only the module objects are read.
(
    cd "${build_dir}"
    gcovr --root /src objs/addon \
        --txt "${report_dir}/summary.txt" \
        --html-details "${report_dir}/index.html" \
        --json "${report_dir}/coverage.json" \
        --print-summary
)
python3 /src/tests/runner/coverage_functions.py "${report_dir}/coverage.json" \
    | tee "${report_dir}/functions.txt"
# The container runs as root; hand the report to the owner of the checkout.
chown -R "$(stat -c %u:%g /src)" /reports
echo "run-tests: coverage report in tests/reports/coverage/index.html"

exit "${status}"
