#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
# (SC2034: EVIDENCE_PATH, EVIDENCE_NAME and CASE_DIR are used by the files that call these functions.)
# Input validation helpers. Sourced by bin/dfir-triage after dfir_common.sh.

# All module names, and the ones that need an external program.
ALL_MODULES="metadata strings binwalk foremost bulk_extractor volatility"
AUTO_MODULES="metadata strings binwalk foremost bulk_extractor"

MODULES=() # filled by parse_module_list

# require_integer NAME VALUE MIN MAX
require_integer() {
    local name=$1 value=$2 min=$3 max=$4
    if [[ ! $value =~ ^[0-9]{1,9}$ ]]; then
        die "$EXIT_USAGE" "$name must be a whole number, got '$value'"
    fi
    # "10#" forces base 10 so that a value such as 08 is not read as an octal number.
    if ((10#$value < min || 10#$value > max)); then
        die "$EXIT_USAGE" "$name must be between $min and $max, got '$value'"
    fi
}

# A case ID becomes a directory name, so only safe characters are allowed. This also
# makes path tricks such as ../ or absolute paths impossible.
validate_case_id() {
    local id=$1
    if [[ ! $id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
        die "$EXIT_USAGE" "invalid --case-id '$id': use 1-64 letters, digits, dot, underscore or hyphen, starting with a letter or digit"
    fi
}

# parse_module_list LIST : fills MODULES; "auto" means every module except volatility.
parse_module_list() {
    local list=$1 name candidate known
    local parts=()
    MODULES=()
    if [[ $list == auto ]]; then
        list=${AUTO_MODULES// /,}
    fi
    # Split on commas without changing IFS for the rest of the function.
    IFS=, read -r -a parts <<<"$list"
    for name in ${parts[@]+"${parts[@]}"}; do
        if [[ -z $name ]]; then
            die "$EXIT_USAGE" "empty module name in --modules (check for doubled or leading commas)"
        fi
        known=0
        for candidate in $ALL_MODULES; do
            if [[ $candidate == "$name" ]]; then
                known=1
            fi
        done
        if ((! known)); then
            die "$EXIT_USAGE" "unknown module '$name' (valid: ${ALL_MODULES// /, }, or 'auto')"
        fi
        MODULES+=("$name")
    done
    if ((${#MODULES[@]} == 0)); then
        die "$EXIT_USAGE" "--modules needs at least one module name"
    fi
}

module_selected() {
    local wanted=$1 name
    for name in "${MODULES[@]}"; do
        if [[ $name == "$wanted" ]]; then
            return 0
        fi
    done
    return 1
}

# validate_evidence_file PATH : sets EVIDENCE_PATH (absolute) and EVIDENCE_NAME.
# The evidence is only ever read. It must be a regular file; directories, devices and
# pipes are refused because their content can change while being read.
validate_evidence_file() {
    local path=$1 directory
    if [[ -z $path ]]; then
        die "$EXIT_USAGE" "no evidence given: use --evidence FILE"
    fi
    if [[ ! -e $path ]]; then
        die "$EXIT_EVIDENCE" "evidence file does not exist: $path"
    fi
    if [[ -d $path ]]; then
        die "$EXIT_EVIDENCE" "evidence must be a single file, not a directory: $path"
    fi
    if [[ ! -f $path ]]; then
        die "$EXIT_EVIDENCE" "evidence is not a regular file: $path"
    fi
    if [[ ! -r $path ]]; then
        die "$EXIT_EVIDENCE" "evidence file is not readable: $path"
    fi
    directory=$(cd -P -- "$(dirname -- "$path")" && pwd) || die "$EXIT_EVIDENCE" "cannot resolve the evidence path: $path"
    EVIDENCE_NAME=$(basename -- "$path")
    EVIDENCE_PATH=$directory/$EVIDENCE_NAME
}

# validate_output_dir DIR CASE_ID : the case directory must not exist yet, so no earlier
# case can ever be overwritten (and, because the evidence exists, it can never be inside it).
# Sets CASE_DIR.
validate_output_dir() {
    local base=$1 case_id=$2
    if [[ -e $base && ! -d $base ]]; then
        die "$EXIT_USAGE" "output path exists and is not a directory: $base"
    fi
    CASE_DIR=${base%/}/$case_id
    if [[ -e $CASE_DIR ]]; then
        die "$EXIT_USAGE" "case directory already exists: $CASE_DIR (choose another --case-id or --output-dir)"
    fi
}
