#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
# (SC2034: DEFAULT_VOL_PLUGINS is used by bin/dfir-triage.)
# Analysis modules. Sourced by bin/dfir-triage after dfir_common.sh, dfir_validate.sh and dfir_hash.sh.
#
# Every module follows the same rules:
#   * it only READS the evidence (the path in WORK_EVIDENCE) and writes inside CASE_DIR;
#   * if its program is not installed it records SKIPPED and says how to install it. Nothing is
#     ever installed automatically and no privileges are requested;
#   * it records OK, FAILED or TIMEOUT, the exit code and start and end time in status.tsv;
#   * the exact command it ran is appended to logs/commands.txt.
#
# Globals read: CASE_DIR, WORK_EVIDENCE, TIMEOUT_SECONDS, STRINGS_LIMIT_MB, STRINGS_MIN_LENGTH, VOL_PLUGINS,
#               STATUS_FILE, COMMANDS_FILE, VERSIONS_FILE

DEFAULT_VOL_PLUGINS="windows.info.Info windows.pslist.PsList windows.pstree.PsTree windows.cmdline.CmdLine windows.netscan.NetScan"

# How to install each optional program (shown when it is missing). We never run these.
install_hint() {
    case $1 in
        binwalk) printf 'Debian/Ubuntu/Kali: sudo apt install binwalk' ;;
        foremost) printf 'Debian/Ubuntu/Kali: sudo apt install foremost' ;;
        bulk_extractor) printf 'Debian/Ubuntu/Kali: sudo apt install bulk-extractor' ;;
        volatility) printf 'Volatility 3: pip install volatility3 (see https://github.com/volatilityfoundation/volatility3)' ;;
        strings) printf 'Debian/Ubuntu/Kali: sudo apt install binutils; macOS: xcode-select --install' ;;
        file) printf 'Debian/Ubuntu/Kali: sudo apt install file' ;;
    esac
}

# --- bookkeeping -------------------------------------------------------------------------------

record_status() {
    # module, status, exit code, start, end, note
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$(one_line "$6")" >>"$STATUS_FILE"
}

skip_module() {
    local module=$1 reason=$2 now
    now=$(utc_now)
    record_status "$module" SKIPPED - "$now" "$now" "$reason"
    log_warn "module $module skipped: $reason"
}

record_command() {
    printf '%s\t%s\n' "$(utc_now)" "$(quote_command "$@")" >>"$COMMANDS_FILE"
}

# Record the version of an external program. Programs differ in how they report it, so a few
# common flags are tried and the first output line that looks like a version number is kept.
record_tool_version() {
    local name=$1 tool=$2 flag line=""
    for flag in --version -V -h; do
        line=$(run_with_timeout 20 "$tool" "$flag" 2>&1 </dev/null | head -n 5 | grep -m 1 -E '[0-9]+\.[0-9]+')
        if [[ -n $line ]]; then
            break
        fi
    done
    printf '%s\t%s\t%s\n' "$name" "$tool" "$(one_line "${line:-version not detected}")" >>"$VERSIONS_FILE"
}

# --- file attributes (collected before any content is read) ---------------------------------

epoch_to_utc() {
    # GNU date takes "-d @seconds", BSD date takes "-r seconds".
    date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf 'unknown'
}

# stat_field GNU_FORMAT BSD_FORMAT : the two stat implementations use different options.
stat_field() {
    stat -c "$1" -- "$WORK_EVIDENCE" 2>/dev/null || stat -f "$2" -- "$WORK_EVIDENCE" 2>/dev/null || printf 'unknown'
}

# Write the file's timestamps and ownership. This runs BEFORE hashing, because reading a
# file can update its access time on some file systems; stat itself does not read the content.
capture_file_attributes() {
    local destination=$1 modified changed accessed
    modified=$(stat_field '%Y' '%m')
    changed=$(stat_field '%Z' '%c')
    accessed=$(stat_field '%X' '%a')
    {
        printf 'path=%s\n' "$(one_line "$EVIDENCE_PATH")"
        printf 'size_bytes=%s\n' "$(size_of "$WORK_EVIDENCE")"
        printf 'modified_utc=%s\n' "$(epoch_to_utc "$modified")"
        printf 'inode_changed_utc=%s\n' "$(epoch_to_utc "$changed")"
        printf 'accessed_utc=%s\n' "$(epoch_to_utc "$accessed")"
        printf 'permissions=%s\n' "$(stat_field '%A' '%Sp')"
        printf 'owner=%s\n' "$(stat_field '%U:%G' '%Su:%Sg')"
    } >"$destination"
}

# --- built-in modules --------------------------------------------------------------------------

module_metadata() {
    local started dir=$CASE_DIR/metadata
    started=$(utc_now)
    if ! command -v file >/dev/null 2>&1; then
        skip_module metadata "the 'file' command is not installed ($(install_hint file))"
        return
    fi
    mkdir -p "$dir"
    record_command file -b -- "$WORK_EVIDENCE"
    file -b -- "$WORK_EVIDENCE" >"$dir/file_type.txt" 2>"$dir/file.stderr.txt"
    file -b --mime-type -- "$WORK_EVIDENCE" >"$dir/mime_type.txt" 2>>"$dir/file.stderr.txt"
    # The first bytes (the "magic number") identify many formats even when the extension lies.
    head -c 64 -- "$WORK_EVIDENCE" | od -A x -t x1 >"$dir/first_64_bytes.hex.txt"
    record_status metadata OK 0 "$started" "$(utc_now)" "file type, MIME type and first bytes recorded"
}

# Extract indicators (IPv4 addresses, URLs, e-mail addresses) from a text file and print
# "count<TAB>type<TAB>value", most frequent first. The extraction is best effort: it is not a
# status-bearing step, so its exit codes (including SIGPIPE from head) are ignored.
extract_iocs() {
    local source_file=$1
    printf 'count\ttype\tvalue\n'
    LC_ALL=C grep -aEo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$source_file" |
        LC_ALL=C awk -F. '$1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255' |
        LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n 100 |
        awk '{ print $1 "\tipv4\t" $2 }'
    LC_ALL=C grep -aEo "https?://[A-Za-z0-9._~:/?#@!\$&()*+,;=%-]+" "$source_file" |
        LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n 100 |
        awk '{ print $1 "\turl\t" $2 }'
    LC_ALL=C grep -aEo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$source_file" |
        LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -n 100 |
        awk '{ print $1 "\temail\t" $2 }'
    return 0
}

module_strings() {
    local started dir=$CASE_DIR/strings size limit_bytes note="full file scanned"
    started=$(utc_now)
    if ! command -v strings >/dev/null 2>&1; then
        skip_module strings "the 'strings' command is not installed ($(install_hint strings))"
        return
    fi
    mkdir -p "$dir"
    size=$(size_of "$WORK_EVIDENCE")
    limit_bytes=$((STRINGS_LIMIT_MB * 1048576))
    if ((size > limit_bytes)); then
        note="only the first $STRINGS_LIMIT_MB MB of $((size / 1048576)) MB were scanned (--strings-limit-mb)"
        log_warn "strings: $note"
    fi
    record_command strings -a -n "$STRINGS_MIN_LENGTH" "(first $limit_bytes bytes of the evidence)"
    # ASCII strings.
    head -c "$limit_bytes" -- "$WORK_EVIDENCE" | LC_ALL=C strings -a -n "$STRINGS_MIN_LENGTH" >"$dir/strings_ascii.txt" 2>"$dir/strings.stderr.txt"
    # Windows stores much text as UTF-16LE (every other byte is 0). Removing the zero bytes turns
    # that text into plain ASCII. This is an approximation: neighbouring strings can be merged.
    head -c "$limit_bytes" -- "$WORK_EVIDENCE" | LC_ALL=C tr -d '\000' | LC_ALL=C strings -a -n 8 >"$dir/strings_utf16le_approx.txt" 2>>"$dir/strings.stderr.txt"
    cat "$dir/strings_ascii.txt" "$dir/strings_utf16le_approx.txt" >"$dir/.combined.tmp"
    extract_iocs "$dir/.combined.tmp" >"$dir/iocs.tsv"
    rm -f -- "$dir/.combined.tmp"
    record_status strings OK 0 "$started" "$(utc_now)" "$note"
}

# --- modules that run an external program --------------------------------------------------

# run_tool_module MODULE OUTPUT_DIR TOOL [ARGS...]
# Runs one external program with the time limit, keeps its stdout and stderr in files and
# records the outcome. A failing or hanging tool never stops the other modules.
run_tool_module() {
    local module=$1 dir=$2 started rc status note
    shift 2
    started=$(utc_now)
    record_tool_version "$module" "$1"
    record_command "$@"
    run_with_timeout "$TIMEOUT_SECONDS" "$@" >"$dir/$module.stdout.txt" 2>"$dir/$module.stderr.txt"
    rc=$?
    case $rc in
        0) status=OK note="finished normally" ;;
        124) status=TIMEOUT note="stopped after $TIMEOUT_SECONDS seconds (--timeout)" ;;
        *) status=FAILED note="exit code $rc; see $module/$module.stderr.txt" ;;
    esac
    record_status "$module" "$status" "$rc" "$started" "$(utc_now)" "$note"
    if [[ $status != OK ]]; then
        log_warn "module $module: $note"
    fi
}

module_binwalk() {
    local tool dir=$CASE_DIR/binwalk
    if ! tool=$(command -v binwalk); then
        skip_module binwalk "binwalk is not installed ($(install_hint binwalk))"
        return
    fi
    mkdir -p "$dir"
    # A plain signature scan: it lists what it finds and extracts nothing.
    run_tool_module binwalk "$dir" "$tool" "$WORK_EVIDENCE"
}

module_foremost() {
    local tool dir=$CASE_DIR/foremost
    if ! tool=$(command -v foremost); then
        skip_module foremost "foremost is not installed ($(install_hint foremost))"
        return
    fi
    mkdir -p "$dir"
    # foremost refuses to write into an existing output directory, so it creates "carved" itself.
    run_tool_module foremost "$dir" "$tool" -i "$WORK_EVIDENCE" -o "$dir/carved"
}

module_bulk_extractor() {
    local tool dir=$CASE_DIR/bulk_extractor
    if ! tool=$(command -v bulk_extractor); then
        skip_module bulk_extractor "bulk_extractor is not installed ($(install_hint bulk_extractor))"
        return
    fi
    mkdir -p "$dir"
    # bulk_extractor also requires that its output directory does not exist yet.
    run_tool_module bulk_extractor "$dir" "$tool" -o "$dir/features" "$WORK_EVIDENCE"
}

# Volatility 3 is installed under different names depending on how it was installed.
find_volatility() {
    local candidate
    if [[ -n ${DFIR_VOLATILITY:-} ]]; then
        command -v "$DFIR_VOLATILITY"
        return
    fi
    for candidate in vol volatility3 vol.py; do
        if command -v "$candidate"; then
            return 0
        fi
    done
    return 1
}

module_volatility() {
    local tool dir=$CASE_DIR/volatility started plugin rc total=0 failed=0 failed_names="" size
    started=$(utc_now)
    if ! tool=$(find_volatility); then
        skip_module volatility "Volatility 3 was not found as vol, volatility3 or vol.py ($(install_hint volatility))"
        return
    fi
    size=$(size_of "$WORK_EVIDENCE")
    if ((size < 1048576)); then
        log_warn "volatility: the evidence is only $size bytes; real memory images are much larger"
    fi
    mkdir -p "$dir"
    record_tool_version volatility "$tool"
    for plugin in $VOL_PLUGINS; do
        total=$((total + 1))
        record_command "$tool" -q -f "$WORK_EVIDENCE" "$plugin"
        run_with_timeout "$TIMEOUT_SECONDS" "$tool" -q -f "$WORK_EVIDENCE" "$plugin" >"$dir/$plugin.txt" 2>"$dir/$plugin.stderr.txt"
        rc=$?
        if ((rc != 0)); then
            failed=$((failed + 1))
            failed_names="$failed_names $plugin(exit $rc)"
        fi
    done
    if ((failed == 0)); then
        record_status volatility OK 0 "$started" "$(utc_now)" "$total plugin(s) finished"
    else
        record_status volatility FAILED 1 "$started" "$(utc_now)" "$failed of $total plugin(s) failed:$failed_names"
        log_warn "module volatility: $failed of $total plugin(s) failed:$failed_names"
    fi
}

run_modules() {
    local module
    for module in "${MODULES[@]}"; do
        log_info "running module: $module"
        case $module in
            metadata) module_metadata ;;
            strings) module_strings ;;
            binwalk) module_binwalk ;;
            foremost) module_foremost ;;
            bulk_extractor) module_bulk_extractor ;;
            volatility) module_volatility ;;
        esac
    done
}

# What each module needs, for --list-modules and --dry-run.
describe_module() {
    local module=$1 tool="" needs=""
    case $module in
        metadata) needs="file" ;;
        strings) needs="strings" ;;
        binwalk | foremost | bulk_extractor) needs=$module ;;
        volatility) needs="vol / volatility3 / vol.py" ;;
    esac
    case $module in
        volatility) tool=$(find_volatility) ;;
        *) tool=$(command -v "$needs") ;;
    esac
    if [[ -n $tool ]]; then
        printf '%-15s available  (%s)\n' "$module" "$tool"
    else
        printf '%-15s MISSING    (needs: %s)\n' "$module" "$needs"
    fi
}
