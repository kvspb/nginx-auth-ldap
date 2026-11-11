# The official nginx image with this module as a dynamic module, loaded
# from nginx.conf. Built from the repository root:
#
#   docker build -f packaging/docker/Dockerfile --build-arg NGINX_VERSION=1.30.6 .
#
# The same recipe as in README.md ("Docker").
ARG NGINX_VERSION=1.30.6

FROM nginx:${NGINX_VERSION} AS build
ARG NGINX_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gcc libc6-dev libldap-dev libpcre2-dev libssl-dev make zlib1g-dev
COPY config LICENSE /src/nginx-auth-ldap/
COPY src /src/nginx-auth-ldap/src
RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar -xz -C /src \
    && cd "/src/nginx-${NGINX_VERSION}" \
    && ./configure --with-compat --with-http_ssl_module \
        --add-dynamic-module=/src/nginx-auth-ldap \
    && make modules

FROM nginx:${NGINX_VERSION}
RUN apt-get update \
    && apt-get install -y --no-install-recommends libldap2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/nginx-*/objs/ngx_http_auth_ldap_module.so /usr/lib/nginx/modules/
COPY LICENSE README.md CHANGELOG.md example.conf /usr/share/doc/nginx-auth-ldap/
RUN sed -i '1i load_module modules/ngx_http_auth_ldap_module.so;' /etc/nginx/nginx.conf
LABEL org.opencontainers.image.title="nginx with nginx-auth-ldap" \
      org.opencontainers.image.description="nginx with the LDAP authentication module loaded" \
      org.opencontainers.image.source="https://github.com/kvspb/nginx-auth-ldap" \
      org.opencontainers.image.licenses="BSD-2-Clause"
