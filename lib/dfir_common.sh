#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
# Shared constants and helpers for dfir-triage. This file is sourced, never executed.
# (SC2034 is disabled because the constants are used by the files that source this one.)

DFIR_VERSION="1.0.0"
PROGRAM_NAME="dfir-triage"

# Exit codes (documented in docs/usage.md).
EXIT_OK=0
EXIT_RUNTIME=1       # the case could not be created or finished
EXIT_USAGE=2         # wrong command line options or values
EXIT_EVIDENCE=3      # evidence file missing, unreadable or not a regular file
EXIT_MODULE_ERRORS=4 # the case finished, but at least one module failed or timed out
EXIT_INTEGRITY=5     # the evidence hash changed during the run: do not trust the results

ESC=$'\033'
TAB=$'\t'

USE_COLOR_STDERR=0
USE_COLOR_STDOUT=0
OPT_QUIET=0
RUN_LOG="" # set once the case directory exists; log lines are also appended to this file

init_color() {
    local mode=$1
    if [[ $mode == never || -n ${NO_COLOR:-} ]]; then
        return 0
    fi
    if [[ -t 2 ]]; then
        USE_COLOR_STDERR=1
    fi
    if [[ -t 1 ]]; then
        USE_COLOR_STDOUT=1
    fi
}

# UTC time in ISO 8601. DFIR_FIXED_TIME exists only so that tests can compare output.
utc_now() {
    if [[ -n ${DFIR_FIXED_TIME:-} ]]; then
        printf '%s' "$DFIR_FIXED_TIME"
    else
        date -u +%Y-%m-%dT%H:%M:%SZ
    fi
}

# Append a line to the case run log (when it exists).
write_run_log() {
    if [[ -n $RUN_LOG ]]; then
        printf '%s %s\n' "$(utc_now)" "$*" >>"$RUN_LOG"
    fi
}

log_info() {
    write_run_log "INFO  $*"
    if ((! OPT_QUIET)); then
        printf '%s: %s\n' "$PROGRAM_NAME" "$*" >&2
    fi
}

log_warn() {
    write_run_log "WARN  $*"
    if ((USE_COLOR_STDERR)); then
        printf '%s: %s[1;33mwarning%s[0m: %s\n' "$PROGRAM_NAME" "$ESC" "$ESC" "$*" >&2
    else
        printf '%s: warning: %s\n' "$PROGRAM_NAME" "$*" >&2
    fi
}

log_error() {
    write_run_log "ERROR $*"
    if ((USE_COLOR_STDERR)); then
        printf '%s: %s[1;31merror%s[0m: %s\n' "$PROGRAM_NAME" "$ESC" "$ESC" "$*" >&2
    else
        printf '%s: error: %s\n' "$PROGRAM_NAME" "$*" >&2
    fi
}

# die EXIT_CODE MESSAGE... : every failure path uses this so errors look the same and carry
# a documented exit code.
die() {
    local code=$1
    shift
    log_error "$*"
    exit "$code"
}

# Reduce text to one printable line so it can be written safely to a report or a log.
one_line() {
    printf '%s' "$1" | LC_ALL=C tr '\t\n\r' '   ' | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177'
}

# Print a command line with every argument shell-quoted, for the record of exact commands.
# LC_ALL=C makes printf %q escape every non-ASCII byte as an octal sequence: bash 3.2 (the macOS
# default) corrupts multi-byte characters such as Hebrew when it quotes them in a UTF-8 locale.
quote_command() {
    local argument out=""
    local LC_ALL=C
    for argument in "$@"; do
        out="$out$(printf '%q' "$argument") "
    done
    printf '%s' "${out% }"
}

# run_with_timeout SECONDS COMMAND [ARGS...]
# Runs a command and stops it after SECONDS (0 = no limit). Returns 124 on timeout, like GNU
# timeout. The macOS default has no timeout command, so a small polling loop is used when
# neither timeout nor gtimeout exists. Only the started process is stopped, not its children.
run_with_timeout() {
    local seconds=$1 pid ticks=0 limit
    shift
    if ((seconds <= 0)); then
        "$@"
        return $?
    fi
    if command -v timeout >/dev/null 2>&1; then
        timeout "$seconds" "$@"
        return $?
    fi
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$seconds" "$@"
        return $?
    fi
    "$@" &
    pid=$!
    limit=$((seconds * 5)) # the loop below ticks five times per second
    while kill -0 "$pid" 2>/dev/null; do
        if ((ticks >= limit)); then
            kill "$pid" 2>/dev/null
            sleep 1
            kill -9 "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            return 124
        fi
        sleep 0.2
        ticks=$((ticks + 1))
    done
    wait "$pid"
}
