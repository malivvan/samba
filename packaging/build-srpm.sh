#!/bin/sh
# Build a source RPM from a git checkout: run from the repository root.
#   packaging/build-srpm.sh
set -e
VERSION=$(sed -n 's/^const Version = "\(.*\)"/\1/p' doc.go)
[ -n "$VERSION" ] || { echo "cannot read the version from doc.go" >&2; exit 1; }
NAME=samba-$VERSION
TOP=$(mktemp -d)
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP/$NAME"
git archive --format=tar HEAD | tar -x -C "$TOP/$NAME"
tar -C "$TOP" -czf "$TOP/$NAME.tar.gz" "$NAME"
rpmbuild -bs \
    --define "_sourcedir $TOP" \
    --define "_srcrpmdir $(pwd)/out" \
    packaging/samba.spec
echo "wrote $(pwd)/out/$NAME-1.src.rpm"
