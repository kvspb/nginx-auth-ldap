#!/bin/sh
# Builds the APT repository from the .deb packages of a release, in a
# Debian container (see the apt job of .github/workflows/packages.yml):
#
#   /dist          dist/<image>/ directories of "make package", e.g.
#                  /dist/debian-bookworm/*.deb
#   /out           the repository: dists/, pool/ and nginx-auth-ldap.asc
#   SIGNING_KEY    the armored secret key that signs the Release files
#
# One suite per distribution release, named by its codename, component
# main; every build replaces the repository as a whole, so it holds the
# packages of the newest release only.
set -eu

: "${SIGNING_KEY:?SIGNING_KEY is required}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends gnupg reprepro >/dev/null

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
printf '%s\n' "${SIGNING_KEY}" | gpg --batch --quiet --import
fingerprint=$(gpg --batch --with-colons --list-secret-keys \
    | awk -F: '/^fpr:/ { print $10; exit }')

work=$(mktemp -d)
mkdir -p "${work}/conf"
: >"${work}/conf/distributions"
for dir in /dist/*/; do
    image=$(basename "${dir}")
    case "${image}" in
        debian-bookworm) codename=bookworm ;;
        debian-trixie) codename=trixie ;;
        ubuntu-24.04) codename=noble ;;
        *) continue ;;
    esac
    if ! grep -q "^Codename: ${codename}\$" "${work}/conf/distributions"; then
        cat >>"${work}/conf/distributions" <<EOF
Origin: nginx-auth-ldap
Label: nginx-auth-ldap
Codename: ${codename}
Architectures: amd64 arm64
Components: main
Description: LDAP authentication module for the nginx of ${codename}
SignWith: ${fingerprint}

EOF
    fi
    for deb in "${dir}"*.deb; do
        reprepro --basedir "${work}" includedeb "${codename}" "${deb}"
    done
done

mkdir -p /out
cp -r "${work}/dists" "${work}/pool" /out/
gpg --batch --armor --export "${fingerprint}" >/out/nginx-auth-ldap.asc
find /out -type f | sort
