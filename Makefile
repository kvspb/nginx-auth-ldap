# Developer entry points. nginx builds the module through ./config, not
# through this file.
#
#   make test                          run the suite against nginx $(NGINX_VERSION)
#   make test PYTEST_ARGS="-k groups"  pass arguments to pytest
#   make test-matrix                   run against every version in NGINX_VERSIONS
#   make coverage                      coverage report in tests/reports/coverage/
#   make test-down                     stop the LDAP server and drop volumes

COMPOSE ?= docker compose -f tests/docker-compose.yml
NGINX_VERSION ?= 1.30.6
# Pre-1.23 header API, current stable, current mainline.
NGINX_VERSIONS ?= 1.22.1 1.30.6 1.31.8
PYTEST_ARGS ?=

.PHONY: test test-matrix coverage test-down

test:
	NGINX_VERSION=$(NGINX_VERSION) $(COMPOSE) run --rm --build tests $(PYTEST_ARGS)

# Stops at the first failing version.
test-matrix:
	@for version in $(NGINX_VERSIONS); do \
		echo "=== nginx $${version} ==="; \
		$(MAKE) --no-print-directory test NGINX_VERSION="$${version}" || exit 1; \
	done

coverage:
	COVERAGE=1 $(MAKE) --no-print-directory test

test-down:
	$(COMPOSE) down -v
