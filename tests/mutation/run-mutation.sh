#!/bin/sh
# Diff-based mutation testing with Mull.
#
# Builds nginx with the module using clang and the Mull IR plugin, so that
# every mutant of the lines changed since MUTATE_BASE is compiled into one
# binary, then lets mull-runner run the pytest suite once per mutant.
#
# Environment:
#   NGINX_VERSION  nginx release to build against (default: 1.30.6)
#   MUTATE_BASE    git ref to diff against (required)
#   MUTATE_TIMEOUT minimum timeout per mutant run in ms (default: 60000)
#   MUTATE_ASAN    1 (default) to build with AddressSanitizer and
#                  NGX_DEBUG_PALLOC, so that a mutant breaking a buffer size
#                  is caught; 0 for a plain, faster build
# Any arguments are passed to pytest (e.g. a test file to run per mutant).
set -eu

: "${NGINX_VERSION:=1.30.6}"
: "${MUTATE_BASE:?set MUTATE_BASE to the git ref to diff against}"
: "${MUTATE_TIMEOUT:=60000}"
: "${MUTATE_ASAN:=1}"

build_dir="/build/nginx-${NGINX_VERSION}-mull"

cc_opt="-O0 -g -grecord-command-line -Wno-error -fpass-plugin=/usr/lib/mull-ir-frontend-${LLVM}"
ld_opt=""
if [ "${MUTATE_ASAN}" = "1" ]; then
    # NGX_DEBUG_PALLOC turns every pool allocation into its own malloc(), so
    # that ASan sees overflows that would otherwise land in pool slack.
    cc_opt="${cc_opt} -fsanitize=address -fno-omit-frame-pointer -DNGX_DEBUG_PALLOC=1"
    ld_opt="-fsanitize=address"
fi
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}"
tarball="/build/nginx-${NGINX_VERSION}.tar.gz"
report_dir=/reports/mutation

# The checkout is owned by the host user and mounted read-only.
git config --global --add safe.directory /src
git -C /src rev-parse --verify --quiet "${MUTATE_BASE}^{commit}" >/dev/null \
    || { echo "run-mutation: unknown git ref ${MUTATE_BASE}"; exit 2; }

# The plugin reads this config at compile time (which lines to mutate) and
# mull-runner reads it at run time.
export MULL_CONFIG=/tmp/mull.yml
cat >"${MULL_CONFIG}" <<EOF
mutators:
  - cxx_all
includePaths:
  - '^/src/.*\.c$'
excludePaths:
  - '^/src/tests/.*'
gitDiffRef: ${MUTATE_BASE}
gitProjectRoot: /src
parallelization:
  # The tests share one LDAP server and change fixture passwords.
  executionWorkers: 1
EOF

if [ ! -f "${tarball}" ]; then
    echo "run-mutation: downloading nginx ${NGINX_VERSION}"
    curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o "${tarball}.part"
    mv "${tarball}.part" "${tarball}"
fi

# Mutants depend on MUTATE_BASE and on the source, so always configure and
# build the module from scratch; nginx core objects are rebuilt as well,
# which keeps this script simple at the cost of a minute per run.
rm -rf "${build_dir}"
mkdir -p "${build_dir}"
tar -xzf "${tarball}" -C "${build_dir}" --strip-components=1
echo "run-mutation: configuring nginx ${NGINX_VERSION} with the Mull plugin"
(
    cd "${build_dir}"
    ./configure \
        --prefix=/tmp/nginx \
        --with-cc="clang-${LLVM}" \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-cc-opt="${cc_opt}" \
        --with-ld-opt="${ld_opt}" \
        --add-module=/src \
        --add-module=/src/tests/modules/rerun_phases >"${build_dir}/configure.log" 2>&1 \
        || { cat "${build_dir}/configure.log"; exit 1; }
)
echo "run-mutation: building (mutants of the diff against ${MUTATE_BASE})"
make -C "${build_dir}" -j"$(nproc)" >"${build_dir}/make.log" 2>&1 \
    || { grep -E "error" "${build_dir}/make.log" || tail -n 50 "${build_dir}/make.log"; exit 1; }

export NGINX_BINARY="${build_dir}/objs/nginx"
"${NGINX_BINARY}" -V 2>&1 | head -n 1

rm -rf "${report_dir}"
mkdir -p "${report_dir}"

cd /src/tests
status=0
# --include-not-covered: the suite drives nginx over HTTP, so Mull cannot
# collect per-test coverage; every mutant on the diff is run.
# --timeout covers the warm-up and baseline runs of the unmutated binary;
# mutants get max(10 x baseline, MUTATE_TIMEOUT).
mull-runner "${NGINX_BINARY}" \
    --include-not-covered \
    --timeout "${MUTATE_TIMEOUT}" \
    --minimum-timeout "${MUTATE_TIMEOUT}" \
    --ld-search-path "/usr/lib/$(uname -m)-linux-gnu" \
    --reporters IDE --reporters Elements \
    --report-dir "${report_dir}" --report-name mutation \
    --test-program python3 \
    -- -m pytest -x -q -p no:cacheprovider "$@" \
    | tee "${report_dir}/mutation.txt" || status=$?

chown -R "$(stat -c %u:%g /src)" /reports
echo "run-mutation: report in tests/reports/mutation/ (mutation.txt, mutation.html)"
exit "${status}"
