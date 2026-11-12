#!/bin/sh
# Builds the libnginx-mod-http-auth-ldap package for the nginx package of
# the Debian or Ubuntu release this runs on, in a container of that
# release (see "make deb"):
#
#   /src     the source tree, read-only
#   /out     where the .deb and the .buildinfo go
#   VERSION  upstream version, e.g. 1.2.1 or 1.2.1+3.gdce534a
#   REVISION Debian revision (default: 1)
#   OWNER    uid:gid to give the files in /out (default: root)
set -eu

: "${VERSION:?VERSION is required}"
: "${REVISION:=1}"

export DEBIAN_FRONTEND=noninteractive
# No -dbgsym package: the release ships the module alone.
export DEB_BUILD_OPTIONS=noddebs

# /etc/os-release has a VERSION of its own: read it in a subshell.
# shellcheck source=/dev/null
os() { (. /etc/os-release && eval "echo \"\${$1}\""); }
codename=$(os VERSION_CODENAME)
case "$(os ID)" in
    debian) suffix="deb$(os VERSION_ID)" ;;
    ubuntu) suffix="ubuntu$(os VERSION_ID)" ;;
    *) echo "build-deb: unsupported distribution $(os ID)" >&2; exit 1 ;;
esac
full_version="${VERSION}-${REVISION}+${suffix}"

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential ca-certificates dpkg-dev >/dev/null

work=/tmp/build/libnginx-mod-http-auth-ldap-${VERSION}
rm -rf /tmp/build
mkdir -p "${work}"
# Only what a build needs: no tests, no packaging of other systems.
cp -r /src/config /src/src /src/LICENSE /src/README.md /src/CHANGELOG.md \
    /src/example.conf "${work}/"
cp -r /src/packaging/debian "${work}/debian"
cat >"${work}/debian/changelog" <<EOF
libnginx-mod-http-auth-ldap (${full_version}) ${codename}; urgency=medium

  * Upstream release ${VERSION}, see changelog.gz.

 -- Valery Komarov <komarov@valerka.net>  $(date -R -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}")
EOF

cd "${work}"
apt-get build-dep -y -qq ./ >/dev/null
dpkg-buildpackage -b -us -uc
mkdir -p /out
cp ../*.deb ../*.buildinfo /out/
if [ -n "${OWNER:-}" ]; then
    chown -R "${OWNER}" /out
fi
ls -l /out
