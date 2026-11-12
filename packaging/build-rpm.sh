#!/bin/sh
# Builds the nginx-mod-http-auth-ldap package for the nginx package of the
# Fedora or Enterprise Linux release this runs on, in a container of that
# release (see "make package"):
#
#   /src     the source tree, read-only
#   /out     where the .rpm goes
#   VERSION  upstream version, e.g. 1.2.1 or 1.2.1+git20261111.dce534a
#   REVISION release of the package (default: 1)
#   OWNER    uid:gid to give the files in /out (default: root)
set -eu

: "${VERSION:?VERSION is required}"
: "${REVISION:=1}"

# nginx-mod-devel is in CRB on Enterprise Linux.
if ! grep -q '^ID=fedora' /etc/os-release; then
    dnf -q -y install dnf-plugins-core
    dnf -q config-manager --set-enabled crb
fi
dnf -q -y install rpm-build

top=/tmp/rpmbuild
name=nginx-auth-ldap-${VERSION}
rm -rf "${top}"
mkdir -p "${top}/SOURCES" "${top}/SPECS" "/tmp/${name}"
# Only what a build needs: no tests, no packaging of other systems.
cp -r /src/config /src/src /src/LICENSE /src/README.md /src/CHANGELOG.md \
    /src/example.conf "/tmp/${name}/"
tar -czf "${top}/SOURCES/${name}.tar.gz" -C /tmp "${name}"

spec=${top}/SPECS/nginx-mod-http-auth-ldap.spec
cp /src/packaging/rpm/nginx-mod-http-auth-ldap.spec "${spec}"
cat >>"${spec}" <<EOF
* $(LC_ALL=C date -u -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}" '+%a %b %d %Y') Valery Komarov <komarov@valerka.net> - ${VERSION}-${REVISION}
- Upstream release ${VERSION}, see CHANGELOG.md.
EOF

dnf -q -y builddep --define "upstream_version ${VERSION}" \
    --define "pkg_release ${REVISION}" "${spec}"
# No -debuginfo/-debugsource packages: the release ships the module alone.
rpmbuild -bb --define "_topdir ${top}" --define "upstream_version ${VERSION}" \
    --define "pkg_release ${REVISION}" --define 'debug_package %{nil}' "${spec}"

mkdir -p /out
cp "${top}"/RPMS/*/*.rpm /out/
if [ -n "${OWNER:-}" ]; then
    chown -R "${OWNER}" /out
fi
ls -l /out
