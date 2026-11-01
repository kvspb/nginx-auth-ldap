# Developer entry points. nginx builds the module through ./config, not
# through this file.
#
#   make test                          run the suite against nginx $(NGINX_VERSION)
#   make test PYTEST_ARGS="-k groups"  pass arguments to pytest
#   make test-matrix                   run against every version in NGINX_VERSIONS
#   make test-builds                   dynamic module, Alpine (musl), OpenSSL 1.1.1
#   make coverage                      coverage report in tests/reports/coverage/
#   make mutate BASE=<ref>             mutation testing of the diff against <ref>
#   make test-down                     stop the LDAP server and drop volumes

COMPOSE ?= docker compose -f tests/docker-compose.yml
NGINX_VERSION ?= 1.30.6
# Pre-1.23 header API, current stable, current mainline.
NGINX_VERSIONS ?= 1.22.1 1.30.6 1.31.8
PYTEST_ARGS ?=
# tests (Debian) or tests-alpine.
RUNNER ?= tests
# The oldest OpenSSL release the module supports.
OPENSSL_OLD ?= 1.1.1w

.PHONY: test test-matrix test-builds coverage mutate test-down

test:
	NGINX_VERSION=$(NGINX_VERSION) $(COMPOSE) run --rm --build $(RUNNER) $(PYTEST_ARGS)

# Stops at the first failing version.
test-matrix:
	@for version in $(NGINX_VERSIONS); do \
		echo "=== nginx $${version} ==="; \
		$(MAKE) --no-print-directory test NGINX_VERSION="$${version}" || exit 1; \
	done

# Builds other than the default one, on the default nginx version.
test-builds:
	DYNAMIC=1 $(MAKE) --no-print-directory test
	$(MAKE) --no-print-directory test RUNNER=tests-alpine
	OPENSSL_VERSION=$(OPENSSL_OLD) $(MAKE) --no-print-directory test

coverage:
	COVERAGE=1 $(MAKE) --no-print-directory test

# MODULE_SRC: checkout to mutate (default: this one); it must contain .git.
mutate:
	@test -n "$(BASE)" || { echo "usage: make mutate BASE=<git ref> [PYTEST_ARGS=...]"; exit 2; }
	MUTATE_BASE=$(BASE) NGINX_VERSION=$(NGINX_VERSION) $(COMPOSE) run --rm --build mutation $(PYTEST_ARGS)

test-down:
	$(COMPOSE) down -v
