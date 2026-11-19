#!/usr/bin/env bash
# shellcheck shell=bash
# Hashing helpers: SHA-256 (always) and MD5 (optional, legacy). Sourced after dfir_common.sh.
#
# Hashes are how an investigator proves that evidence was not changed: the SHA-256 is taken
# before any tool touches the file and again afterwards, and the two must be identical.

# Print the SHA-256 of a file as 64 hex characters, using whichever tool the system has.
sha256_of() {
    local file=$1 output
    if command -v sha256sum >/dev/null 2>&1; then
        output=$(sha256sum -- "$file") || return 1
    elif command -v shasum >/dev/null 2>&1; then
        output=$(shasum -a 256 -- "$file") || return 1
    elif command -v openssl >/dev/null 2>&1; then
        output=$(openssl dgst -sha256 -r -- "$file") || return 1
    else
        log_error "no SHA-256 tool found (need sha256sum, shasum or openssl)"
        return 1
    fi
    printf '%s' "${output%% *}"
}

md5_of() {
    local file=$1 output
    if command -v md5sum >/dev/null 2>&1; then
        output=$(md5sum -- "$file") || return 1
        printf '%s' "${output%% *}"
    elif command -v md5 >/dev/null 2>&1; then
        md5 -q -- "$file"
    elif command -v openssl >/dev/null 2>&1; then
        output=$(openssl dgst -md5 -r -- "$file") || return 1
        printf '%s' "${output%% *}"
    else
        return 1
    fi
}

# Size of a file in bytes, the same on Linux and macOS.
size_of() {
    local count
    count=$(wc -c <"$1") || return 1
    printf '%s' "${count//[[:space:]]/}"
}

# Write a hash file in the format "sha256sum -c" understands: "<hash>  <file name>".
write_hash_file() {
    local hash=$1 name=$2 destination=$3
    printf '%s  %s\n' "$hash" "$name" >"$destination"
}
