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
#   make package [PACKAGE_IMAGE=...]   package for the nginx of a distribution
#   make package-smoke                 install it in a clean container and try it
#   make image [IMAGE=...]             the nginx image with the module
#   make image-smoke                   try that image

COMPOSE ?= docker compose -f tests/docker-compose.yml
NGINX_VERSION ?= 1.30.6
# Pre-1.23 header API, current stable, current mainline.
NGINX_VERSIONS ?= 1.22.1 1.30.6 1.31.8
PYTEST_ARGS ?=
# tests (Debian) or tests-alpine.
RUNNER ?= tests
# The oldest OpenSSL release the module supports.
OPENSSL_OLD ?= 1.1.1w
# The distribution to package for, as a container image (see packaging/).
PACKAGE_IMAGE ?= debian:bookworm
# 1.2.1 on the tag v1.2.1, else 1.2.1+git20261111.dce534a.
PACKAGE_VERSION ?= $(shell packaging/version.sh)
PACKAGE_DIR ?= $(CURDIR)/dist/$(subst :,-,$(PACKAGE_IMAGE))
PACKAGE_BUILD ?= build-$(patsubst debian,deb,$(patsubst ubuntu,deb,$(patsubst fedora,rpm,$(patsubst almalinux,rpm,$(firstword $(subst :, ,$(PACKAGE_IMAGE))))))).sh

# The Docker image of packaging/docker, on the nginx image of NGINX_VERSION.
IMAGE ?= nginx-auth-ldap:$(NGINX_VERSION)

.PHONY: test test-matrix test-builds coverage mutate test-down package package-smoke image image-smoke

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

# Into dist/<image>/, e.g. dist/debian-bookworm/.
package:
	rm -rf $(PACKAGE_DIR) && mkdir -p $(PACKAGE_DIR)
	docker run --rm -v $(CURDIR):/src:ro -v $(PACKAGE_DIR):/out \
		-e VERSION=$(PACKAGE_VERSION) -e OWNER=$$(id -u):$$(id -g) \
		-e SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct) \
		$(PACKAGE_IMAGE) /src/packaging/$(PACKAGE_BUILD)

package-smoke:
	PACKAGE_IMAGE=$(PACKAGE_IMAGE) PACKAGE_DIR=$(PACKAGE_DIR) \
		$(COMPOSE) run --rm package-smoke

image:
	docker build -f packaging/docker/Dockerfile \
		--build-arg NGINX_VERSION=$(NGINX_VERSION) -t $(IMAGE) .

# The smoke test of the packages, on the image with no package to install.
image-smoke:
	mkdir -p $(CURDIR)/dist/empty
	PACKAGE_IMAGE=$(IMAGE) PACKAGE_DIR=$(CURDIR)/dist/empty \
		$(COMPOSE) run --rm package-smoke
