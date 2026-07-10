#!/usr/bin/env bash

# Custom spec handling for Packit's `fix-spec-file` action (.packit.yaml).
#
# Copr-only: sync Version/Release/commit from HEAD; keep forge HTTPS Source0.
# Drops Source1 (vendor tarball); sets %%packit_no_vendor_tarball for online %%prep.

set -uexo pipefail

PACKAGE=conmon-v3
SPEC_FILE=rpm/${PACKAGE}.spec

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
COMMIT=$(git rev-parse HEAD)

sed -i "s/^%global upstream_version.*/%global upstream_version ${VERSION}/" "${SPEC_FILE}"
sed -i "s/^%global commit.*/%global commit ${COMMIT}/" "${SPEC_FILE}"
sed -i "s/^Release:.*/Release: ${PACKIT_RPMSPEC_RELEASE}%{?dist}/" "${SPEC_FILE}"

if ! grep -q '^%global packit_no_vendor_tarball' "${SPEC_FILE}"; then
	sed -i '/^Name:/a %global packit_no_vendor_tarball 1' "${SPEC_FILE}"
fi
sed -i "/^Source1/d" "${SPEC_FILE}"
