#!/bin/sh
# Prints the package version of the checked-out commit: 1.2.1 on the tag
# v1.2.1, else the newest release in CHANGELOG.md with the date and the
# commit, 1.2.1+git20261111.dce534a, which sorts after 1.2.1 and before
# 1.2.2 for dpkg and rpm. Release tags sit on merge commits of master, so
# git describe on dev would find an older one.
set -eu

cd "$(dirname "$0")/.."

tag=$(git tag --points-at HEAD | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)
if [ -n "${tag}" ]; then
    echo "${tag#v}"
    exit 0
fi

release=$(sed -n 's/^## \[\([0-9][0-9.]*\)\].*/\1/p' CHANGELOG.md | head -n 1)
: "${release:?no release heading in CHANGELOG.md}"
echo "${release}+git$(git log -1 --format=%cd --date=format:%Y%m%d).$(git rev-parse --short HEAD)"
