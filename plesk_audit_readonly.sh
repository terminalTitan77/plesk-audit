#!/bin/bash
# Read-only Linux server audit, Plesk edition 1.0.0, 2026-10-08.
# Bash 4+ and existing Linux utilities only. No website Python/PHP scripts are executed; Plesk read-only CLI may use its own runtime.
# No installations, upgrades, configuration/service changes or scans; report file is written.
# Output is shown on stdout and automatically saved as audit-report-DDMonYY.txt.
# Normal OS read side effects (atime, audit logs, DNS/HTTP logs) may still occur.
# This is an evidence collector, not a penetration test or a compliance guarantee.
# Sources and the limits of each check are documented by --help.

if (( BASH_VERSINFO[0] < 4 )); then
    printf 'ERROR: Bash 4 or newer is required.\n' >&2; exit 2
fi
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -o pipefail
shopt -s nullglob

usage() {
cat <<'HELP'
PLESK LINUX AUDIT 1.0.0 (adapted from supplied Linux audit 1.3.1)
Run: sudo bash plesk_audit_readonly.sh [options]

  --offline                  No DNS or public vendor HTTPS queries
  --no-package-check         Skip repository candidate queries (default)
  --package-check            Enable cache-only package candidate queries
  --ip IPv4                  Explicit public/mail IPv4, useful with NAT
  --http-url URL              Optional HTTP(S) HEAD endpoint; repeatable
  --webroot /absolute/path    CMS root; repeatable, replaces defaults
  --backup-dir /abs/path      Artifact root; repeatable, replaces defaults
  --expected-backup-bytes N   Minimum size for one matched local backup set
  --report /abs/path          Existing malware/rootkit report
  --max-report-days N         Scan report maximum age (default 20)
  --backup-max-days N         Backup artifact recency threshold (default 2)
  --cpu-max N                 CPU/load threshold percent (default 85)
  --ram-max N                 RAM threshold percent (default 85)
  --disk-max N                Disk/inode threshold percent (default 85)
  --queue-max N               Mail queue threshold (default 100)
  --baseline /abs/file.tsv    Reviewed version/support reference data
  --help                     This guide

Requires root, Bash 4.2+, Linux Plesk, timeout and standard existing utilities.
Does not install, upgrade, repair, restart, change configuration, create backups,
execute website code, scan for malware, or clean files. PHP is run only with
-n -v (no php.ini/extensions). Plesk read-only CLI and SELECT queries may create
normal access/audit logs. File reads may update atime. Package checks default
OFF; --package-check uses existing caches, never apt update or an installer.
Online mode queries public vendor metadata and DNSBL/PTR; --offline disables
network checks, including explicit HTTP endpoints. No IP-discovery API is used.

Writes stdout to audit-report-DDMonYY.txt in the current directory, mode 0600.
Existing reports are not overwritten; repeat runs get a time/PID suffix.
Run from a trusted root-owned directory, not a website or shared writable path.
Exit 0 means collection finished, NOT all checks passed; 2 = invalid environment
or options; 3 = report write failure. Runtime may be several minutes on busy hosts.

38 checklist items, same ITEM/STATUS/ISSUE/RECOMMENDATION fields as the original.
Legacy item spelling is retained for parser compatibility. NA/UNVERIFIED means
manual review, not a pass. Installed firewall/Imunify360/scanner classifications
retain the original audit policy; presence is not proof of enforcement.

Plesk paths: /etc/psa/psa.conf HTTPD_VHOSTS_D and DUMP_D (read as plain data),
/var/www/vhosts, /opt/plesk/php/*, generated per-site PHP configuration.
CMS discovery is bounded per root, depth 12, one filesystem, no website execution.
Custom roots/mounts need --webroot. PHP handler inventory is informational;
installed versions and INI candidates do not prove effective per-site settings.
Plesk version is read from local version data. Panel updates/microupdates remain
NA unless a reviewed baseline proves a newer release; matching base versions
cannot prove every microupdate is installed. No Plesk installer is invoked.

BASELINE: tab-separated, never sourced. Exact key, latest version, support-end
YYYY-MM-DD, reviewed YYYY-MM-DD, source; use '-' for unknown. Reviewed <=30 days.
Keys: panel:plesk:18.0.74 (example only); os:ubuntu:24.04; php:8.3;
cms:wordpress:6.8; pkg:nginx. OS latest must be '-'. Package versions are exact
inventory versions, including RPM epoch. Validate vendor backport entitlement.
Unknown OS/CMS/stack lifecycles remain NA; outdated is not automatically EOL.

Scan report default: /root/scripts/malware-scan-report.txt, <=20 MiB and <=20 days.
Bobcares section findings are recognized, but an empty section is NOT proof of a
completed clean scan. Clean requires an explicit completed scan with positive
coverage and zero findings, with no error/warning marker. Supported summaries:
MALWARE_SCAN_COMPLETED: YES
MALWARE_FILES_SCANNED: <positive integer>
MALWARE_INFECTED_FILES: <nonnegative integer>
ROOTKIT_SCAN_COMPLETED: YES
ROOTKIT_CHECKS_PERFORMED: <positive integer>
ROOTKIT_FOUND: <nonnegative integer>
ClamAV/rkhunter completed summaries also supported. Never fabricate these fields.

Backup configuration: SELECT of allowlisted BackupsScheduled scalar columns,
server-level rows only; no credentials queried or printed. Version/schema errors
remain NA. Schedule/retention does not prove successful execution. Per-subscription,
customer, reseller, extension, and custom cron backups require separate review.
Read-only scheduled-backup --list is used to corroborate daily/weekly/monthly
labels; unrecognized output stays NA. Local backup_info XML identifies candidates;
metadata alone can represent configuration-only or remote backups. Matching file
sizes are candidate sizes, not guaranteed complete incremental-chain size. Latest
PMM log path and warning/error counts are informational and never used to invent
successful completion. RECENT LAST BACKUP stays NA until completion is manually
verified. No archive extraction, remote access, or restore is performed.

Plesk references (reviewed 2026-10-08):
https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/php_handler-php-handlers.72490/
https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/server_pref-interface-and-system-preferences.37785/
https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/scheduledbackup-managing-scheduled-backup-tasks.80003/
https://support.plesk.com/hc/en-us/articles/12377059635351-How-to-disable-scheduled-backup-tasks-over-the-CLI
https://support.plesk.com/hc/en-us/articles/12377966554135-Local-backup-structure-in-Plesk-for-Linux
https://support.plesk.com/hc/en-us/articles/12377716359319-How-to-find-version-of-Plesk-installed-on-server
HELP
}

OFFLINE=0; NO_PACKAGE_CHECK=1; TARGET_IP=''; SCAN_REPORT=/root/scripts/malware-scan-report.txt
MAX_REPORT_DAYS=20; BACKUP_MAX_DAYS=2; CPU_MAX=85; RAM_MAX=85; DISK_MAX=85
QUEUE_MAX=100; EXPECTED_BACKUP_BYTES=0; BASELINE=''
WEBROOTS=(); BACKUP_DIRS=(); HTTP_URLS=()
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
need_value() { (( $# >= 2 )) && [[ -n $2 ]] || die "Missing value for $1"; }
uint() { [[ $1 =~ ^[0-9]{1,12}$ ]] && [[ $1 == 0 || $1 != 0* ]]; }
while (( $# )); do
    case "$1" in
        --help|-h) usage; exit 0;;
        --offline) OFFLINE=1; shift;;
        --no-package-check) NO_PACKAGE_CHECK=1; shift;;
        --package-check) NO_PACKAGE_CHECK=0; shift;;
        --ip) need_value "$@"; TARGET_IP=$2; shift 2;;
        --http-url) need_value "$@"; [[ $2 =~ ^https?://[^[:space:]]+$ ]] || die 'Invalid HTTP URL'; HTTP_URLS+=("$2"); shift 2;;
        --webroot) need_value "$@"; [[ $2 == /* && -d $2 && ! -L $2 ]] || die 'Webroot must be an existing absolute, non-symlink directory'; WEBROOTS+=("$2"); shift 2;;
        --backup-dir) need_value "$@"; [[ $2 == /* && -d $2 && ! -L $2 ]] || die 'Backup root must be an existing absolute, non-symlink directory'; BACKUP_DIRS+=("$2"); shift 2;;
        --report) need_value "$@"; [[ $2 == /* ]] || die 'Report path must be absolute'; SCAN_REPORT=$2; shift 2;;
        --baseline) need_value "$@"; [[ $2 == /* && -f $2 && -r $2 && ! -L $2 ]] || die 'Baseline must be a readable absolute regular file, not a symlink'; BASELINE=$2; shift 2;;
        --max-report-days|--backup-max-days|--cpu-max|--ram-max|--disk-max|--queue-max|--expected-backup-bytes)
            need_value "$@"; uint "$2" || die "Invalid integer for $1"
            case "$1" in
                --max-report-days) MAX_REPORT_DAYS=$2;;
                --backup-max-days) BACKUP_MAX_DAYS=$2;;
                --cpu-max) CPU_MAX=$2;; --ram-max) RAM_MAX=$2;; --disk-max) DISK_MAX=$2;;
                --queue-max) QUEUE_MAX=$2;; --expected-backup-bytes) EXPECTED_BACKUP_BYTES=$2;;
            esac; shift 2;;
        *) die "Unknown option: $1 (use --help)";;
    esac
done
(( EUID == 0 )) || die 'Run as root for protected configuration and password-age reads.'
for dep in awk sed grep find stat date timeout sort head tail tr cut cat sleep tee; do
    command -v "$dep" >/dev/null 2>&1 || die "Required existing utility missing: $dep (nothing installed)"
done
for pct in "$CPU_MAX" "$RAM_MAX" "$DISK_MAX"; do (( pct > 0 && pct <= 100 )) || die 'Percent thresholds must be 1..100'; done
(( MAX_REPORT_DAYS <= 3650 && BACKUP_MAX_DAYS <= 3650 )) || die 'Day thresholds must be <=3650'
[[ -f /usr/local/psa/version || -f /opt/psa/version ]] || die 'Plesk for Linux was not detected.'
psa_value() {
    awk -v key="$1" '$1==key {v=$2;gsub(/^["\047]|["\047]$/,"",v);if(v ~ /^\//)print v;exit}' /etc/psa/psa.conf 2>/dev/null
}
PLESK_VHOSTS=$(psa_value HTTPD_VHOSTS_D); PLESK_VHOSTS=${PLESK_VHOSTS:-/var/www/vhosts}
PLESK_DUMPS=$(psa_value DUMP_D); PLESK_DUMPS=${PLESK_DUMPS:-/var/lib/psa/dumps}
(( ${#WEBROOTS[@]} )) || WEBROOTS=("$PLESK_VHOSTS")
(( ${#BACKUP_DIRS[@]} )) || BACKUP_DIRS=("$PLESK_DUMPS")
umask 077
AUDIT_REPORT_FILE="audit-report-$(date +%d%b%y).txt"
[[ -e $AUDIT_REPORT_FILE || -L $AUDIT_REPORT_FILE ]] && AUDIT_REPORT_FILE="audit-report-$(date +%d%b%y-%H%M%S)-$$.txt"
set -C
exec 9> "$AUDIT_REPORT_FILE" || die 'Cannot safely create report in current directory.'
set +C
exec > >(tee /dev/fd/9)
TEE_PID=$!
finish_report() {
    local rc=$?
    exec 1>&- 9>&-
    wait "$TEE_PID" || { printf 'ERROR: Report write failed.\n' >&2; exit 3; }
    exit "$rc"
}
trap finish_report EXIT

NOW=$(date +%s); TODAY=$(date -u +%F)
have() { command -v "$1" >/dev/null 2>&1; }
run() { timeout -k 2s 15s "$@" 2>/dev/null; }
flat() { tr '\n\r\t' '   ' | tr -cd '\40-\176' | cut -c 1-6000; }
emit() {
    local recommendation=$4
    [[ -n $recommendation ]] && recommendation=$(client_recommendation "$1" "$2" "$recommendation")
    printf '[ITEM] : %s\n[STATUS] : %s\n[ISSUE] : %s\n[RECOMMENDATION] : %s\n\n' \
        "$1" "$2" "$(printf '%s' "$3" | flat)" "$(printf '%s' "$recommendation" | flat)"
}
section() { AUDIT_SECTION=${1%% *}; printf '\nSECTION %s\n%s\n\n' "$1" '============================================================'; }
client_recommendation() { printf '%s' "$3"; }
active() {
    local name
    for name in "$@"; do
        if have systemctl && [[ -d /run/systemd/system ]] && run systemctl is-active --quiet "$name"; then return 0; fi
        if have pgrep && run pgrep -x "$name" >/dev/null; then return 0; fi
    done
    return 1
}
os_value() { awk -F= -v k="$1" '$1==k {v=substr($0,index($0,"=")+1); gsub(/^"|"$/,"",v); print v; exit}' /etc/os-release 2>/dev/null; }
OS_ID=$(os_value ID); OS_VERSION=$(os_value VERSION_ID); OS_NAME=$(os_value PRETTY_NAME)
[[ -n $OS_NAME ]] || OS_NAME=$(head -c 300 /etc/redhat-release 2>/dev/null)
KERNEL=$(run uname -r); HOST=$(run hostname)
PKGS=''; PKG_KIND=unknown; PKG_DIAGNOSTIC=''; PKG_QUERY_OK=0
query_rpm_inventory() {
    local raw rc
    raw=$(timeout -k 2s 60s rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\n' 2>&1); rc=$?
    if (( rc==0 )); then
        PKGS=$(printf '%s\n' "$raw" | awk -F '\t' 'NF==3 && $1 ~ /^[A-Za-z0-9_+.-]+$/ {e=$2;if(e=="(none)")e=0;if(e ~ /^[0-9]+$/)print $1 "\t" e ":" $3}')
        [[ -n $PKGS ]] && { PKG_KIND=rpm; PKG_QUERY_OK=1; return 0; }
    fi
    PKG_DIAGNOSTIC+="RPM inventory failed/empty (exit=$rc); $(printf '%s' "$raw" | head -n 2 | flat); "; return 1
}
query_deb_inventory() {
    local raw rc
    raw=$(timeout -k 2s 60s dpkg-query -W '-f=${db:Status-Status}\t${binary:Package}\t${Version}\n' 2>&1); rc=$?
    if (( rc==0 )); then
        PKGS=$(printf '%s\n' "$raw" | awk -F '\t' '$1=="installed" {print $2 "\t" $3}')
        [[ -n $PKGS ]] && { PKG_KIND=deb; PKG_QUERY_OK=1; return 0; }
    fi
    PKG_DIAGNOSTIC+="Debian inventory failed/empty (exit=$rc); "; return 1
}
# An auxiliary dpkg-query must not suppress the real RPM database.
case "$OS_ID" in
    debian|ubuntu|linuxmint) have dpkg-query && query_deb_inventory; [[ $PKG_QUERY_OK == 1 ]] || { have rpm && query_rpm_inventory; };;
    *) have rpm && query_rpm_inventory; [[ $PKG_QUERY_OK == 1 ]] || { have dpkg-query && query_deb_inventory; };;
esac
PKG_DIAGNOSTIC+="Selected=$PKG_KIND; installed package rows=$(printf '%s\n' "$PKGS" | awk 'NF{n++}END{print n+0}')."
pkgmatch() { printf '%s\n' "$PKGS" | awk -F '\t' -v re="$1" '$1 ~ re {print}'; }

# Baselines are data, not executable shell. Expired/invalid rows never authorize a pass.
declare -A BL_LATEST BL_EOL BL_SOURCE
BASELINE_NOTE='No reviewed external baseline supplied.'
if [[ -n $BASELINE ]]; then
    accepted=0; rejected=0
    while IFS=$'\t' read -r key latest eol reviewed source extra; do
        [[ -z $key || $key == \#* ]] && continue
        rd=$(date -u -d "$reviewed" +%s 2>/dev/null)
        if [[ ! $reviewed =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ || ! $rd =~ ^[0-9]+$ ]] ||
           (( rd > NOW || NOW-rd > 30*86400 )) || [[ -z $source || -n $extra ]] ||
           [[ ! $key =~ ^(os|php|cms|panel|pkg):[a-zA-Z0-9_.:+-]+$ ]] ||
           [[ ! $latest =~ ^[-a-zA-Z0-9_.:+~]+$ ]] ||
           [[ $eol != - && ! $eol =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            ((rejected++)); continue
        fi
        if [[ $eol != - ]] && ! date -u -d "$eol" +%s >/dev/null 2>&1; then ((rejected++)); continue; fi
        BL_LATEST["$key"]=$latest; BL_EOL["$key"]=$eol; BL_SOURCE["$key"]=$source; ((accepted++))
    done < "$BASELINE"
    BASELINE_NOTE="Reviewed baseline rows accepted=$accepted rejected=$rejected (maximum review age 30 days)."
fi

public_v4() {
    local a b c d tail
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d tail <<< "$1"
    a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d))
    (( a<=255 && b<=255 && c<=255 && d<=255 )) || return 1
    (( a>0 && a<224 && a!=10 && a!=127 )) || return 1
    (( a==169 && b==254 || a==172 && b>=16 && b<=31 || a==192 && b==168 || a==100 && b>=64 && b<=127 )) && return 1
    (( a==192 && b==0 || a==192 && b==2 || a==198 && (b==18 || b==19 || b==51) || a==203 && b==0 && c==113 )) && return 1
    return 0
}
if [[ -n $TARGET_IP ]]; then public_v4 "$TARGET_IP" || die '--ip must be a public IPv4 address'; fi
ips=()
if have ip; then
    while read -r ipval; do public_v4 "$ipval" && ips+=("$ipval"); done < <(run ip -o -4 addr show scope global | awk '{split($4,a,"/");print a[1]}' | sort -u)
fi
IP_NOTE='Explicit IP supplied; confirm this is also the mail egress IP.'; IP_MISMATCH=0
if [[ -n $TARGET_IP ]] && ! printf '%s\n' "${ips[@]}" | grep -Fxq "$TARGET_IP"; then
    IP_NOTE='WARNING: explicit IP is not assigned to a detected public interface. Confirm NAT/mail egress ownership; this may be the wrong server IP.'; IP_MISMATCH=1
fi
if [[ -z $TARGET_IP ]]; then
    if (( ${#ips[@]} == 1 )); then TARGET_IP=${ips[0]}; IP_NOTE='Single local public interface IP selected; NAT/mail egress still needs confirmation.'
    else IP_NOTE="UNVERIFIED: found ${#ips[@]} public interface IPv4 addresses; provide --ip for the actual server/mail IP."; fi
fi

# Report summaries: no scan or arbitrary report command is executed.
# The Bobcares report is plain-text evidence only; nothing inside it is executed.
REPORT_TEXT=''; REPORT_FRESH=0; REPORT_INFO='Report missing, unreadable, not regular, or a symlink.'
OUTDATED_CMS_TEXT=''; MALWARE_SECTION_TEXT=''; ROOTKIT_SECTION_TEXT=''
REPORT_CMS_ENTRIES=''; REPORT_CMS_COUNT=0; REPORT_CMS_EXAMPLES=''
REPORT_MALWARE_COUNT=0; REPORT_MALWARE_FILE_COUNT=0; REPORT_MALWARE_EXAMPLES=''
ROOTKIT_CHECKED=''; ROOTKIT_POSSIBLE=''; ROOTKIT_EVIDENCE=''
REPORT_CMS_SECTION_PRESENT=0; REPORT_MALWARE_SECTION_PRESENT=0; REPORT_ROOTKIT_SECTION_PRESENT=0
if [[ -f $SCAN_REPORT && -r $SCAN_REPORT && ! -L $SCAN_REPORT ]]; then
    mtime=$(stat -c %Y -- "$SCAN_REPORT" 2>/dev/null); rsize=$(stat -c %s -- "$SCAN_REPORT" 2>/dev/null)
    if [[ $mtime =~ ^[0-9]+$ && $rsize =~ ^[0-9]+$ ]]; then
        age=$((NOW-mtime))
        REPORT_INFO="Report=$SCAN_REPORT; age=$((age/86400)) days; bytes=$rsize."
        if (( age >= 0 && age <= MAX_REPORT_DAYS*86400 && rsize > 0 && rsize <= 20971520 )); then
            REPORT_TEXT=$(run cat -- "$SCAN_REPORT"); REPORT_FRESH=1
        else REPORT_INFO+=' Rejected for decisive status: stale/future/empty or larger than 20 MiB.'; fi
    fi
fi
report_has() { printf '%s\n' "$REPORT_TEXT" | grep -Eiq -- "$1"; }
report_section() {
    local start_re=$1 end_re=${2:-}
    printf '%s\n' "$REPORT_TEXT" | awk -v s="$start_re" -v e="$end_re" '
        $0 ~ s {inside=1; next}
        inside && e!="" && $0 ~ e {exit}
        inside {print}
    '
}
section_has_problem_marker() {
    printf '%s\n' "$1" | grep -Eiq '(^|[[:space:]\[])((ERROR|FAILED|ABORTED|WARNING))([:][[:space:]]|[[:space:]\]]|$)'
}
summary_num() {
    printf '%s\n' "$REPORT_TEXT" | awk -v re="$1" 'BEGIN{re=tolower(re);n=-1} tolower($0) ~ re {v=$0;sub(/^[^:]*:[[:space:]]*/,"",v);sub(/[[:space:]]*$/,"",v);if(v ~ /^[0-9]+$/ && v+0>n)n=v+0} END{if(n>=0)print n}'
}

MALWARE_RESULT=unknown; ROOTKIT_RESULT=unknown
if (( REPORT_FRESH )); then
    report_has '^[[:space:]]*Outdated CMS Report[[:space:]]*$' && REPORT_CMS_SECTION_PRESENT=1
    report_has '^[[:space:]]*Malware Scan Report[[:space:]]*$' && REPORT_MALWARE_SECTION_PRESENT=1
    report_has '^[[:space:]]*Rootkit Scan Report[[:space:]]*$' && REPORT_ROOTKIT_SECTION_PRESENT=1

    if (( REPORT_CMS_SECTION_PRESENT )); then
        OUTDATED_CMS_TEXT=$(report_section '^[[:space:]]*Outdated CMS Report[[:space:]]*$' '^[[:space:]]*Malware Scan Report[[:space:]]*$')
        # Versionfinder output is treated as evidence because this section is explicitly
        # the report's outdated-CMS/package result. Header/update chatter is excluded.
        REPORT_CMS_ENTRIES=$(printf '%s\n' "$OUTDATED_CMS_TEXT" | awk '
            /^[[:space:]]*(WordPress|Joomla!?|Drupal|Moodle|phpBB3|phpBB|osCommerce|PHPMailer|Magento|PrestaShop|OpenCart|TYPO3|MediaWiki)([[:space:]]|$)/ {
                line=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", line); print line
            }' | sort -u)
        REPORT_CMS_COUNT=$(printf '%s\n' "$REPORT_CMS_ENTRIES" | awk 'NF{n++}END{print n+0}')
        REPORT_CMS_EXAMPLES=$(printf '%s\n' "$REPORT_CMS_ENTRIES" | head -n 12 | flat)
    fi

    if (( REPORT_MALWARE_SECTION_PRESENT )); then
        MALWARE_SECTION_TEXT=$(report_section '^[[:space:]]*Malware Scan Report[[:space:]]*$' '^[[:space:]]*Rootkit Scan Report[[:space:]]*$')
        REPORT_MALWARE_COUNT=$(printf '%s\n' "$MALWARE_SECTION_TEXT" | grep -Ec '^[[:space:]]*Malware:[[:space:]]*[^[:space:]].*' || true)
        REPORT_MALWARE_FILE_COUNT=$(printf '%s\n' "$MALWARE_SECTION_TEXT" | grep -Ec '^[[:space:]]*File:[[:space:]]*/' || true)
        REPORT_MALWARE_EXAMPLES=$(printf '%s\n' "$MALWARE_SECTION_TEXT" | awk '
            /^[[:space:]]*File:[[:space:]]*/ {f=$0; sub(/^[[:space:]]*/,"",f); next}
            /^[[:space:]]*Malware:[[:space:]]*/ {m=$0; sub(/^[[:space:]]*/,"",m); if(f!="") print f " | " m; else print m; f=""}
        ' | head -n 8 | flat)
        if (( REPORT_MALWARE_COUNT > 0 )); then
            MALWARE_RESULT=found
        elif ! section_has_problem_marker "$MALWARE_SECTION_TEXT"; then
            MALWARE_RESULT=unknown
        fi
    fi

    if (( REPORT_ROOTKIT_SECTION_PRESENT )); then
        ROOTKIT_SECTION_TEXT=$(report_section '^[[:space:]]*Rootkit Scan Report[[:space:]]*$' '')
        ROOTKIT_CHECKED=$(printf '%s\n' "$ROOTKIT_SECTION_TEXT" | sed -nE 's/^[[:space:]]*(Rootkits checked|Files checked|ROOTKIT_CHECKS_PERFORMED)[[:space:]]*:[[:space:]]*([0-9]+)[[:space:]]*$/\2/ip' | sort -n | tail -n 1)
        ROOTKIT_POSSIBLE=$(printf '%s\n' "$ROOTKIT_SECTION_TEXT" | sed -nE 's/^[[:space:]]*(Possible rootkits|ROOTKIT_FOUND)[[:space:]]*:[[:space:]]*([0-9]+)[[:space:]]*$/\2/ip' | sort -n | tail -n 1)
        ROOTKIT_EVIDENCE="Rootkits checked=${ROOTKIT_CHECKED:-unknown}; possible rootkits=${ROOTKIT_POSSIBLE:-unknown}."
        if [[ $ROOTKIT_POSSIBLE =~ ^[0-9]+$ ]] && (( ROOTKIT_POSSIBLE > 0 )); then
            ROOTKIT_RESULT=found
        elif [[ $ROOTKIT_POSSIBLE == 0 && $ROOTKIT_CHECKED =~ ^[0-9]+$ ]] && (( ROOTKIT_CHECKED > 0 )) && ! section_has_problem_marker "$ROOTKIT_SECTION_TEXT"; then
            ROOTKIT_RESULT=clean
        fi
    fi

    # Fallback support for older ClamAV/rkhunter/audit-summary formats.
    mi=$(summary_num '^[[:space:]]*(Infected files|MALWARE_INFECTED_FILES)[[:space:]]*:')
    mc=$(summary_num '^[[:space:]]*(Scanned files|MALWARE_FILES_SCANNED)[[:space:]]*:')
    ri=$(summary_num '^[[:space:]]*(Possible rootkits|ROOTKIT_FOUND)[[:space:]]*:')
    rc=$(summary_num '^[[:space:]]*(Rootkits checked|Files checked|ROOTKIT_CHECKS_PERFORMED)[[:space:]]*:')
    if [[ $MALWARE_RESULT == unknown ]]; then
        if [[ $mi =~ ^[0-9]+$ ]] && (( mi > 0 )); then MALWARE_RESULT=found
        elif [[ $mi == 0 && $mc =~ ^[0-9]+$ ]] && (( mc > 0 )) && report_has 'SCAN SUMMARY|^MALWARE_SCAN_COMPLETED:[[:space:]]*YES[[:space:]]*$'; then MALWARE_RESULT=clean; fi
        report_has '^/[^:]+: .+ FOUND[[:space:]]*$' && MALWARE_RESULT=found
    fi
    if [[ $ROOTKIT_RESULT == unknown ]]; then
        if [[ $ri =~ ^[0-9]+$ ]] && (( ri > 0 )); then ROOTKIT_RESULT=found
        elif [[ $ri == 0 && $rc =~ ^[0-9]+$ ]] && (( rc > 0 )) && report_has 'System checks summary|^ROOTKIT_SCAN_COMPLETED:[[:space:]]*YES[[:space:]]*$|^[[:space:]]*Rootkit Scan Report[[:space:]]*$'; then ROOTKIT_RESULT=clean; fi
        report_has '^[[:space:]]*Checking.*INFECTED' && ROOTKIT_RESULT=found
    fi
fi
if section_has_problem_marker "$REPORT_TEXT"; then
    [[ $MALWARE_RESULT == clean ]] && MALWARE_RESULT=unknown
    [[ $ROOTKIT_RESULT == clean ]] && ROOTKIT_RESULT=unknown
fi
# Bounded file discovery; partial discovery never establishes full coverage.
CMS_LIST=''; CMS_SCOPE=''; CMS_PARTIAL=0
for root in "${WEBROOTS[@]}"; do
    [[ -d $root ]] || continue
    CMS_SCOPE+="$root "
    files=$(timeout -k 2s 45s find "$root" -xdev -maxdepth 12 \
        \( -type d \( -name node_modules -o -name .git -o -name cache -o -name vendor \) -prune \) -o \
        \( -type f \( -path '*/wp-includes/version.php' -o -path '*/core/lib/Drupal.php' -o \
        -path '*/includes/bootstrap.inc' -o -path '*/administrator/manifests/files/joomla.xml' -o -name version.php \) -print \) 2>/dev/null)
    (( $? == 0 )) || CMS_PARTIAL=1
    while IFS= read -r file; do
        [[ -n $file ]] || continue
        ver=''; product=''
        case "$file" in
            */wp-includes/version.php) product=wordpress; ver=$(sed -nE "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */core/lib/Drupal.php) product=drupal; ver=$(sed -nE "s/.*const VERSION[[:space:]]*=[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */includes/bootstrap.inc) product=drupal; ver=$(sed -nE "s/.*define\(['\"]VERSION['\"],[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */administrator/manifests/files/joomla.xml) product=joomla; ver=$(sed -nE 's/.*<version>([0-9.]+)<\/version>.*/\1/p' "$file" | head -n 1);;
            */version.php)
                if [[ -f ${file%/*}/lib/moodlelib.php ]]; then
                    product=moodle; ver=$(sed -nE "s/^[[:space:]]*\\\$release[[:space:]]*=[[:space:]]*['\"]([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p" "$file" | head -n 1)
                fi;;
        esac
        [[ -n $product && -n $ver ]] && CMS_LIST+="$product"$'\t'"$ver"$'\t'"$file"$'\n'
    done <<< "$files"
done
CMS_LIST=$(printf '%s' "$CMS_LIST" | sort -u)

PANEL=plesk
PANEL_VERSION_RAW=$(head -c 200 /usr/local/psa/version 2>/dev/null)
[[ -n $PANEL_VERSION_RAW ]] || PANEL_VERSION_RAW=$(head -c 200 /opt/psa/version 2>/dev/null)
PANEL_VER=$(printf '%s\n' "$PANEL_VERSION_RAW" | awk '{print $1}')
PLESK_HANDLERS='UNVERIFIED: plesk CLI unavailable'
if have plesk; then
    ph=$(run plesk bin php_handler --list); phrc=$?
    if (( phrc==0 )); then PLESK_HANDLERS=$(printf '%s' "$ph" | flat)
    else PLESK_HANDLERS="UNVERIFIED: php_handler --list exit=$phrc"; fi
fi

PHP_LIST=''; declare -A SEEN_PHP
for bin in /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /opt/remi/php*/root/usr/bin/php /opt/alt/php*/usr/bin/php /opt/plesk/php/*/bin/php; do
    [[ -x $bin && ${bin##*/} =~ ^php([0-9.]*)?$ ]] || continue
    resolved=$(run readlink -f "$bin"); [[ -n $resolved ]] || resolved=$bin
    [[ -n ${SEEN_PHP[$resolved]:-} ]] && continue; SEEN_PHP[$resolved]=1
    # -n avoids extensions/configuration/autoload; no PHP application code is run.
    ver=$(run "$bin" -n -v | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1)
    [[ -n $ver ]] && PHP_LIST+="$ver"$'\t'"$bin"$'\n'
done
PHP_LIST=$(printf '%s' "$PHP_LIST" | sort -u)
WEB_PKGS=$(pkgmatch '^(sw-nginx|nginx|apache2|httpd|litespeed|openlitespeed|lsws)([-:]|$)')
DB_PKGS=$(pkgmatch '^([Mm][Yy][Ss][Qq][Ll]|mysql-community|mariadb|MariaDB|postgresql|percona|Percona|redis|mongodb)([-:]|$)')
OTHER_PKGS=$(pkgmatch '^(psa-)?(postfix|qmail|exim|sendmail|dovecot|bind|bind9|unbound|powerdns|pdns|openssh|openssl|proftpd|pure-ftpd|vsftpd)([-:]|$)')
WEB_BINARIES=''; DB_BINARIES=''
for cmd in nginx httpd apache2; do
    if have "$cmd"; then
        binary_version=$(timeout -k 2s 10s "$cmd" -v 2>&1 | head -n 2 | flat)
        WEB_BINARIES+="$cmd: $binary_version; "
    fi
done
for cmd in mysqld mariadbd; do
    have "$cmd" && DB_BINARIES+="$cmd: $(run "$cmd" --no-defaults --version | flat); "
done
for cmd in postgres redis-server mongod; do
    have "$cmd" && DB_BINARIES+="$cmd: $(run "$cmd" --version | head -n 2 | flat); "
done

printf 'READ-ONLY PLESK AUDIT 1.0.0 | %s UTC\n' "$(date -u '+%F %T')"
printf 'Host: %s | OS: %s | Kernel: %s | Panel: %s %s\n' "$HOST" "$OS_NAME" "$KERNEL" "$PANEL" "$PANEL_VER"
printf 'Target IPv4: %s | %s\n' "${TARGET_IP:-unverified}" "$IP_NOTE"
printf 'Package inventory: %s\n' "$PKG_DIAGNOSTIC"
printf 'Network checks: %s | %s\n' "$([[ $OFFLINE == 1 ]] && printf disabled || printf 'DNS and public vendor HTTPS enabled; website HEAD only for supplied URLs')" "$BASELINE_NOTE"
printf 'Report file: %s (0600)\n' "$AUDIT_REPORT_FILE"
printf 'Unknowns are not passes. No installations/upgrades, configuration changes or scans. Plesk/status queries may write normal logs/locks; cache-only package queries are optional. See --help.\n'

section 'A : Threat Protection'
fw_installed=''; fw_issues=''; fw_rules=''; rules_known=0
for cmd in csf iptables nft firewall-cmd ufw imunify360-agent; do have "$cmd" && fw_installed+="$cmd "; done
[[ -d /etc/csf ]] && fw_installed+='CSF-config '
active lfd && fw_installed+='LFD-running '
active fail2ban && fw_installed+='Fail2Ban-running '
for svc in firewalld nftables iptables imunify360; do
    if have systemctl && [[ -d /run/systemd/system ]]; then
        load=$(run systemctl show "$svc" -p LoadState | sed -n 's/^LoadState=//p')
        if [[ $load == loaded ]] && ! active "$svc"; then fw_issues+="$svc service inactive (rules may persist independently); "; fi
    fi
done
if [[ -f /etc/csf/csf.disable ]]; then fw_issues+='CSF disable marker exists; '; fi
if [[ -r /etc/csf/csf.conf ]] && grep -Eq '^[[:space:]]*TESTING[[:space:]]*=[[:space:]]*"?1' /etc/csf/csf.conf; then fw_issues+='CSF TESTING=1; '; fi
if have iptables; then
    rules=$(run iptables -S); rc=$?
    if (( rc == 0 )); then
        rules_known=1
        drops=$(printf '%s\n' "$rules" | grep -Ec -- '^-P INPUT (DROP|REJECT)|^-A .* -j (DROP|REJECT)( |$)')
        fw_rules+="IPv4 filter has $drops restrictive policy/rule entries (reachability not proven); "
    else fw_issues+='IPv4 rules unreadable; '; fi
fi
if have ip6tables; then
    rules6=$(run ip6tables -S)
    if (( $? == 0 )); then fw_rules+="IPv6 restrictive entries=$(printf '%s\n' "$rules6" | grep -Ec -- '^-P INPUT (DROP|REJECT)|^-A .* -j (DROP|REJECT)( |$)'); "; else fw_issues+='IPv6 rules unreadable; '; fi
fi
if have nft; then
    nrules=$(run nft list ruleset)
    if (( $? == 0 )); then rules_known=1; fw_rules+="nft restrictive statements=$(printf '%s\n' "$nrules" | grep -Ec '(^|[[:space:];])(drop|reject)([[:space:];]|$)'); "; fi
fi
if [[ -n $fw_installed ]]; then fw_status=ACTIVE; else fw_status=INACTIVE; fi
emit 'SYSTEM FIREWALL' "$fw_status" "Installed/detected: ${fw_installed:-none}. $fw_issues $fw_rules Presence is not proof of effective inbound protection. Cloud/Sucuri controls are not locally verifiable." 'Review effective IPv4/IPv6 INPUT policies, rule order, exposed ports, trusted IPs, and disabled/test-mode products. Coordinate one consistent firewall policy; do not enable competing managers blindly.'

scanners=$(pkgmatch '(clamav|clamd|imunify|maldet|rkhunter|chkrootkit)' | head -n 30 | flat)
scanner_status=INACTIVE; scanner_ev="Installed packages: ${scanners:-none detected}. "; malware_tool=0
for cmd in clamscan clamdscan maldet imunify360-agent imunify-antivirus; do
    if have "$cmd"; then scanner_ev+="$cmd present; "; malware_tool=1; fi
done
if active clamd clamd@scan clamav-daemon; then
    scanner_ev+='Clam daemon process/service running; '
    if have clamdscan && run clamdscan --ping=1 >/dev/null; then
        scanner_ev+='clamd PING succeeded; '
        sig_recent=0
        for f in /var/lib/clamav/daily.cvd /var/lib/clamav/daily.cld /var/clamav/daily.cvd /var/clamav/daily.cld ; do
            [[ -f $f ]] || continue; t=$(stat -c %Y "$f" 2>/dev/null)
            [[ $t =~ ^[0-9]+$ ]] && (( NOW>=t && NOW-t<=7*86400 )) && sig_recent=1
        done
        if (( sig_recent )); then scanner_status=ACTIVE; scanner_ev+='Signature-file mtime within 7 days (signature version not authenticated). '
        else scanner_ev+='UNVERIFIED: signature freshness. '; fi
    fi
fi
if active imunify360 imunify-antivirus; then
    scanner_ev+='Imunify service running; '
    imunify_cmd=''; have imunify360-agent && imunify_cmd=imunify360-agent
    [[ -n $imunify_cmd ]] || { have imunify-antivirus && imunify_cmd=imunify-antivirus; }
    if [[ -n $imunify_cmd ]]; then
        imunify_config=$(run "$imunify_cmd" config show --json); imunify_rc=$?
        if (( imunify_rc==0 )) && printf '%s\n' "$imunify_config" | grep -Eq '"enable_scan_inotify"[[:space:]]*:[[:space:]]*true([,[:space:]}]|$)'; then
            scanner_status=ACTIVE; scanner_ev+='Agent responds and realtime scanning is configured enabled; licensing/signatures and full coverage still need review. '
        else scanner_ev+='Agent response or realtime-scan enablement unverified; licensing/protection needs console review. '; fi
        # Never output full Imunify configuration (may contain notification details).
        unset imunify_config
    fi
fi
[[ $MALWARE_RESULT != unknown && $malware_tool == 1 ]] && { scanner_status=ACTIVE; scanner_ev+="Recent completed scan summary detected: $MALWARE_RESULT. "; }
emit 'MALWARE SCANNER' "$scanner_status" "$scanner_ev Enabled scheduling/realtime coverage is not proven; $REPORT_INFO" 'If operation or coverage is unverified, review scanner health, signature updates, licensing and completed scan history. Arrange a scan separately if required; none was run.'

login_status=INACTIVE; login_ev=''; IMUNIFY_LOGIN_ACTIVE=0; IMUNIFY_LOGIN_BLOCKING=0
if have fail2ban-client; then
    fstatus=$(run fail2ban-client status)
    jails=$(printf '%s\n' "$fstatus" | sed -nE 's/.*Jail list:[[:space:]]*(.*)/\1/p' | tr ',' ' ')
    for jail in $jails; do
        [[ $jail =~ ^[A-Za-z0-9_.-]+$ ]] || continue
        js=$(run fail2ban-client status "$jail"); acts=$(run fail2ban-client get "$jail" actions)
        if [[ -n $js && -n $acts ]] && ! printf '%s' "$acts" | grep -Eiq 'error|invalid|sorry'; then
            # Only known blocking actions count; email-only jails do not.
            if printf '%s' "$acts" | grep -Eiq 'iptables|nftables|firewallcmd|ufw|route|ipset'; then login_status=ACTIVE; login_ev+="Fail2Ban jail $jail responds with blocking-action configuration; "; fi
        fi
    done
fi
if active lfd && [[ -r /etc/csf/csf.conf ]] &&
   grep -Eq '^[[:space:]]*LF_SSHD[[:space:]]*=[[:space:]]*"?[1-9][0-9]*' /etc/csf/csf.conf &&
   ! grep -Eq '^[[:space:]]*TESTING[[:space:]]*=[[:space:]]*"?1' /etc/csf/csf.conf && [[ ! -e /etc/csf/csf.disable ]]; then
    login_status=ACTIVE; login_ev+='LFD running with positive LF_SSHD threshold and CSF not marked disabled/testing; '
fi
# Imunify360 can provide failed-login/brute-force detection even when CSF/LFD
# are disabled. An active resident therefore satisfies this DETECTION item. Query the
# read-only Imunify configuration to report whether explicit PAM/OSSEC blocking is on.
if active imunify360; then
    IMUNIFY_LOGIN_ACTIVE=1; login_status=ACTIVE
    login_ev+='Imunify360 resident service active; audit policy recognizes Imunify360 as the failed malicious-login detection mechanism; '
    if have imunify360-agent; then
        i360_login_cfg=$(run imunify360-agent config show --json); i360_login_rc=$?
        if (( i360_login_rc == 0 )) && [[ -n $i360_login_cfg ]]; then
            i360_compact=$(printf '%s' "$i360_login_cfg" | tr -d '[:space:]')
            i360_controls=''
            printf '%s' "$i360_compact" | grep -Eq '"PAM":\{[^}]*"enable":true' && i360_controls+='PAM SSH/FTP brute-force protection, '
            printf '%s' "$i360_compact" | grep -Eq '"PAM":\{[^}]*"exim_dovecot_protection":true' && i360_controls+='Exim/Dovecot brute-force protection, '
            printf '%s' "$i360_compact" | grep -Eq '"PAM":\{[^}]*"ftp_protection":true' && i360_controls+='FTP brute-force protection, '
            printf '%s' "$i360_compact" | grep -Eq '"OSSEC":\{[^}]*"active_response":true' && i360_controls+='OSSEC Active Response, '
            if [[ -n $i360_controls ]]; then
                IMUNIFY_LOGIN_BLOCKING=1; i360_controls=${i360_controls%, }; login_ev+="Imunify360 blocking controls enabled: $i360_controls; "
            else
                login_ev+='Imunify360 config query succeeded; explicit PAM/OSSEC active-response blocking was not confirmed, while detection remains ACTIVE by the resident-service criterion; '
            fi
        else
            login_ev+='Imunify360 resident is active; detailed PAM/OSSEC configuration query was unavailable; '
        fi
        unset i360_login_cfg i360_compact i360_controls
    fi
fi
[[ $login_status == INACTIVE ]] && login_ev+='No operational failed-login detection/protection mechanism confirmed. '
emit 'FAILED LOGIN DETETCTION' "$login_status" "$login_ev No controlled ban test was performed." 'Verify SSH/application login protection, thresholds, exclusions and recent incidents. The audit performs read-only status/configuration queries only.'

waf_pkgs=$(pkgmatch '(mod_security|modsecurity|imunify|naxsi)' | flat)
waf_paths=''; waf_mode=''
for dir in /etc/httpd /etc/apache2 /etc/nginx /usr/local/lsws/conf; do
    [[ -d $dir ]] || continue
    matches=$(timeout -k 2s 15s grep -rIlE --include='*.conf' '^[[:space:]]*(SecRuleEngine|modsecurity|modsecurity_rules_file|enableSecurity)' "$dir" 2>/dev/null)
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        waf_paths+="$f; "
        waf_mode+=$(grep -E '^[[:space:]]*(SecRuleEngine|modsecurity[[:space:]])' "$f" | head -n 10 | flat)
    done <<< "$matches"
done
waf_status=INACTIVE; waf_runtime='UNVERIFIED runtime enforcement.'; waf_mapped=0
imunify360_present=0
if [[ -n $(pkgmatch '^imunify360([_-]|$)') ]] || have imunify360-agent || [[ -d /usr/share/imunify360 || -d /opt/imunify360 ]]; then
    imunify360_present=1
    waf_status=ACTIVE
    waf_runtime='Imunify360 components detected; audit policy marks WEB APP FIREWALL ACTIVE. Per-vhost blocking mode/ruleset coverage still requires review.'
fi
if have pgrep; then
    for pname in httpd apache2 nginx lshttpd; do
        for pid in $(run pgrep -x "$pname"); do
            [[ $pid =~ ^[0-9]+$ && -r /proc/$pid/maps ]] || continue
            grep -Eiq '(mod_security2|ngx_http_modsecurity|libmodsecurity)\.so' "/proc/$pid/maps" && waf_mapped=1
        done
    done
fi
# Live ModSecurity evidence supplements the installed-Imunify360 classification.
if (( waf_mapped )); then
    (( imunify360_present )) || waf_runtime='ModSecurity library mapped by a live web process; blocking enforcement not yet confirmed.'
    today_error=$(date '+%a %b %d'); today_audit=$(date '+%d/%b/%Y')
    for log in /var/log/httpd/error_log /var/log/apache2/error.log /var/log/nginx/error.log /var/log/httpd/modsec_audit.log /var/log/apache2/modsec_audit.log; do
        [[ -f $log && -r $log ]] || continue
        if run tail -n 2000 "$log" | grep -F -e "$today_error" -e "$today_audit" | grep -Eq 'ModSecurity: Access denied with code (403|406|429)'; then
            waf_status=ACTIVE; waf_runtime="Live mapped ModSecurity plus today's blocking event in $log (some request coverage only)."; break
        fi
    done
fi
plesk_waf_mode='unknown'
if have plesk; then
    pw=$(run plesk bin server_pref --show-web-app-firewall); pwrc=$?
    if (( pwrc==0 )); then
        plesk_waf_mode=$(printf '%s\n' "$pw" | sed -nE 's/^[[:space:]]*([Rr]ule engine|[Ww][Aa][Ff] rule engine|waf-rule-engine|[Mm]ode):[[:space:]]*(on|off|detection-only|On|Off|DetectionOnly)[[:space:]]*$/\2/p' | head -n 1)
        plesk_waf_mode=${plesk_waf_mode:-unknown}
        [[ ${plesk_waf_mode,,} == on && $waf_mapped == 1 ]] && waf_status=ACTIVE
    fi
    waf_runtime+=" Plesk server WAF mode=$plesk_waf_mode; query exit=$pwrc; per-subscription overrides and nginx routing require review."
    unset pw
fi
emit 'WEB APP FIREWALL' "$waf_status" "$waf_runtime Packages: ${waf_pkgs:-none detected}. Config candidates: ${waf_paths:-none}. Modes: ${waf_mode:-unknown}. Files can be excluded, overridden or DetectionOnly; no test request sent." 'Review loaded modules, effective vhost configuration, enabled rulesets and audit logs with the developer team. Confirm blocking mode and all-site coverage; externally managed WAFs need manual verification.'

rootkit_tools=''; for cmd in rkhunter chkrootkit; do have "$cmd" && rootkit_tools+="$cmd "; done
rootkit_status=INACTIVE; [[ -n $rootkit_tools ]] && rootkit_status=ACTIVE
emit 'ROOTKIT SCANNER' "$rootkit_status" "Installed tools: ${rootkit_tools:-not found}. Recent report result=$ROOTKIT_RESULT. $REPORT_INFO Tool availability is the ACTIVE criterion for this item; no rootkit scan was executed by the audit." 'Verify scheduled execution and a recent completed report. Review rootkit warnings against a known baseline; a warning is not automatically proof of compromise.'

# Read-only version references. TLS is verified; only public vendor URLs are used.
fetch_metadata() {
    (( OFFLINE )) && return 1
    have curl || return 1
    timeout -k 2s 22s curl -q -f -sS --proto '=https' --proto-redir '=https' \
        --connect-timeout 5 --max-time 20 --max-filesize 2097152 -- "$1" 2>/dev/null
}
json_version() {
    # Numeric release strings only; never interpret JSON as shell or PHP code.
    grep -oE '"'"$1"'"[[:space:]]*:[[:space:]]*"[0-9]+(\.[0-9]+){1,3}"' |
        head -n 1 | sed -E 's/.*:[[:space:]]*"([0-9.]+)"/\1/'
}
PANEL_REFERENCE_NOTE='Plesk release/channel/microupdate currency needs reviewed vendor evidence; installer never invoked.'

# Live vendor OS reference is informational and never executes retrieved content.
OS_VENDOR_LATEST=''; OS_VENDOR_REFERENCE_URL=''; OS_VENDOR_REFERENCE_NOTE='Vendor OS website reference unavailable.'
os_vendor_raw=''
if (( OFFLINE )); then
    OS_VENDOR_REFERENCE_NOTE='Vendor OS website check skipped by --offline.'
else
    case "$OS_ID" in
        cloudlinux)
            OS_VENDOR_REFERENCE_URL='https://docs.cloudlinux.com/introduction/'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'CloudLinux OS [0-9]+' | grep -oE '[0-9]+' | sort -Vu | tail -n 1);;
        almalinux)
            OS_VENDOR_REFERENCE_URL='https://wiki.almalinux.org/release-notes/'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'AlmaLinux( OS)? [0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | sort -Vu | tail -n 1);;
        rocky)
            OS_VENDOR_REFERENCE_URL='https://wiki.rockylinux.org/rocky/version/'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'Rocky( Linux)? [0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | sort -Vu | tail -n 1);;
        ubuntu)
            OS_VENDOR_REFERENCE_URL='https://ubuntu.com/about/release-cycle'
            os_vendor_raw=$(fetch_metadata "$OS_VENDOR_REFERENCE_URL")
            OS_VENDOR_LATEST=$(printf '%s\n' "$os_vendor_raw" | grep -oE 'Ubuntu [0-9]{2}\.04 LTS' | grep -oE '[0-9]{2}\.04' | sort -Vu | tail -n 1);;
    esac
    [[ -n $OS_VENDOR_LATEST ]] && OS_VENDOR_REFERENCE_NOTE="Live vendor website latest release reference=$OS_VENDOR_LATEST." 
fi
unset os_vendor_raw

# Standard-support lifecycle flag used by the Software Updates recommendation.
# ELS/paid extended support is deliberately treated as separate from standard support.
OS_STANDARD_EOL=0
case "$OS_ID:$OS_VERSION" in
    cloudlinux:7|cloudlinux:7.*) [[ $TODAY > 2024-06-30 ]] && OS_STANDARD_EOL=1;;
    centos:7|centos:7.*) [[ $OS_NAME != *Stream* && $TODAY > 2024-06-30 ]] && OS_STANDARD_EOL=1;;
    centos:8|centos:8.*) [[ $OS_NAME != *Stream* && $TODAY > 2021-12-31 ]] && OS_STANDARD_EOL=1;;
    ubuntu:14.04|ubuntu:16.04|ubuntu:18.04|ubuntu:20.04) OS_STANDARD_EOL=1;;
esac
WP_LATEST=''; WP_REFERENCE_NOTE='WordPress HTTPS release metadata unavailable.'
if printf '%s\n' "$CMS_LIST" | grep -q '^wordpress'; then
    wp_json=$(fetch_metadata 'https://api.wordpress.org/core/version-check/1.7/')
    if (( $?==0 )); then
        WP_LATEST=$(printf '%s' "$wp_json" | json_version current)
        [[ -n $WP_LATEST ]] && WP_REFERENCE_NOTE="Latest official WordPress release=$WP_LATEST (live HTTPS)."
    fi
fi
declare -A PHP_LIVE_LATEST
while IFS=$'\t' read -r ver bin; do
    [[ -n $ver ]] || continue; branch=${ver%.*}
    case "$branch" in 8.2|8.3|8.4|8.5) ;; *) continue;; esac
    [[ -n ${PHP_LIVE_LATEST[$branch]+set} ]] && continue
    php_json=$(fetch_metadata "https://www.php.net/releases/index.php?json&version=$branch"); php_fetch_rc=$?
    latest=''; (( php_fetch_rc==0 )) && latest=$(printf '%s' "$php_json" | json_version version)
    [[ $latest == "$branch".* ]] || latest=''
    PHP_LIVE_LATEST[$branch]=$latest
done <<< "$PHP_LIST"

# DNF/YUM availability query. Online mode may refresh repository metadata/cache,
# but no install/upgrade transaction is invoked. Offline mode is cache-only.
RPM_UPDATES=''; RPM_CHECK_OK=0; RPM_CACHE_DAYS=unknown; RPM_CHECK_NOTE='RPM package check unavailable.'
RPM_MANAGER=''
if [[ $PKG_KIND == rpm && $NO_PACKAGE_CHECK == 0 ]]; then
    have dnf && RPM_MANAGER=dnf; [[ -n $RPM_MANAGER ]] || { have yum && RPM_MANAGER=yum; }
    if [[ -n $RPM_MANAGER ]]; then
        rpm_opts=(-C --noplugins --setopt=history_record=false --setopt=skip_if_unavailable=false --setopt=logfile=/dev/null)
        update_raw=$(timeout -k 2s 90s "$RPM_MANAGER" "${rpm_opts[@]}" -q check-update 2>&1); update_rc=$?
        mode_note='cache-only, plugins disabled; cache freshness requires review'
        if (( update_rc==0 || update_rc==100 )); then
            RPM_UPDATES=$(printf '%s\n' "$update_raw" | awk '$1 ~ /\.(x86_64|i[3-6]86|noarch|aarch64|ppc64le|s390x)$/ && NF>=3 && $2 ~ /^[0-9]/ {n=$1;sub(/\.[^.]+$/,"",n);print n "\t" $2 "\t" $3}')
            RPM_CHECK_OK=1
            RPM_CHECK_NOTE="$RPM_MANAGER check-update succeeded ($mode_note), exit=$update_rc, candidate rows=$(printf '%s\n' "$RPM_UPDATES" | awk 'NF{n++}END{print n+0}')."
        else
            RPM_CHECK_NOTE="UNVERIFIED: $RPM_MANAGER check-update failed, exit=$update_rc (124 means timeout). $(printf '%s\n' "$update_raw" | tail -n 4 | flat)"
        fi
        cache_root=/var/cache/dnf; [[ $RPM_MANAGER == yum ]] && cache_root=/var/cache/yum
        ct=$(timeout -k 2s 10s find "$cache_root" -maxdepth 6 -type f -name repomd.xml -printf '%T@\n' 2>/dev/null | sort -n | head -n 1); ct=${ct%%.*}
        [[ $ct =~ ^[0-9]+$ ]] && (( NOW>=ct )) && RPM_CACHE_DAYS=$(((NOW-ct)/86400))
        RPM_CHECK_NOTE+=" Oldest cached repomd.xml age=$RPM_CACHE_DAYS days."
        if [[ ! $RPM_CACHE_DAYS =~ ^[0-9]+$ ]] || (( RPM_CACHE_DAYS>1 )); then RPM_CHECK_OK=0; fi
        unset update_raw rpm_opts
    fi
fi

APT_CANDIDATES=''; APT_AGE='unknown'; APT_OK=0
if [[ $PKG_KIND == deb && $NO_PACKAGE_CHECK == 0 ]] && have apt-cache; then
    list_time=$(find /var/lib/apt/lists -maxdepth 1 -type f \( -name '*InRelease' -o -name '*Release' \) -printf '%T@\n' 2>/dev/null | sort -n | head -n 1)
    list_time=${list_time%%.*}
    if [[ $list_time =~ ^[0-9]+$ ]] && (( NOW >= list_time )); then APT_AGE=$(((NOW-list_time)/86400)); fi
    # Candidate reads are limited to the relevant installed packages plus kernel.
    wanted=$(printf '%s\n' "$PKGS" | awk -F '\t' '$1 ~ /^(linux-image|linux-headers|plesk-php|sw-nginx|php|nginx|apache2|mariadb|mysql|postgresql|redis|mongodb|postfix|exim|sendmail|dovecot|bind|unbound|pdns|openssh|openssl|proftpd|pure-ftpd|vsftpd)/{print $1}')
    if [[ -n $wanted ]]; then
        mapfile -t pkgargs <<< "$wanted"
        pol=$(timeout -k 2s 45s apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy "${pkgargs[@]}" 2>/dev/null)
        if (( $? == 0 )); then
            APT_CANDIDATES=$(printf '%s\n' "$pol" | awk '/^[^[:space:]].*:$/ {p=$0;sub(/:$/,"",p)} /^[[:space:]]*Candidate:/ {print p "\t" $2}')
            [[ $APT_AGE =~ ^[0-9]+$ ]] && (( APT_AGE <= 1 )) && APT_OK=1
        fi
    fi
fi
OFFPEAK='Ask the client for an approved off-peak maintenance time before any upgrade/update; test application compatibility and arrange rollback first.'
package_updates() {
    local item=$1 inventory=$2 binaries=${3:-} n v candidate key count=0 pending=0 unknown=0 ev=''
    if [[ -z $inventory && $item != 'OTHER SOFTWARES' ]]; then emit "$item" NA "No matching packages detected; source/container installs may exist. Binary version evidence: ${binaries:-none found}." "Review actual service inventory and vendor release channel. $OFFPEAK"; return; fi
    while IFS=$'\t' read -r n v; do
        [[ -n $n ]] || continue; ((count++)); key="pkg:$n"; candidate=${BL_LATEST[$key]:-}
        if [[ -n $candidate && $candidate != - ]]; then
            if [[ $v != "$candidate" ]]; then ((unknown++)); ev+="$n=$v reviewed-reference=$candidate (difference; upgrade direction needs vendor verification); "
            else ev+="$n=$v matches reviewed reference; "; fi
        elif [[ $PKG_KIND == rpm ]]; then
            candidate=$(printf '%s\n' "$RPM_UPDATES" | awk -F '\t' -v p="$n" '$1==p{print $2;exit}')
            if [[ -n $candidate ]]; then
                ((pending++)); ev+="$n installed=$v repository-candidate=$candidate; "
            elif (( RPM_CHECK_OK )); then
                ev+="$n=$v (no update candidate reported by successful $RPM_MANAGER check-update); "
            else
                ((unknown++)); ev+="$n=$v (package availability check failed/skipped); "
            fi
        elif [[ $PKG_KIND == deb ]]; then
            candidate=$(printf '%s\n' "$APT_CANDIDATES" | awk -F '\t' -v p="$n" '$1==p{print $2;exit}')
            if [[ -n $candidate && $candidate != '(none)' ]] && run dpkg --compare-versions "$v" lt "$candidate"; then
                ((pending++)); ev+="$n=$v candidate=$candidate; "
            elif [[ -n $candidate && $candidate != '(none)' && $APT_OK == 1 ]] && run dpkg --compare-versions "$v" ge "$candidate"; then
                ev+="$n=$v (no newer candidate in Debian cache); "
            else ((unknown++)); ev+="$n=$v (candidate availability unverified); "; fi
        else ((unknown++)); ev+="$n=$v; "; fi
    done <<< "$inventory"
    # OTHER SOFTWARES also acts as the catch-all for successful DNF/YUM update
    # candidates not already represented by the web/database/PHP component checks.
    # This prevents kernel, kmod-lve and other system-package candidates from being
    # hidden merely because they are outside the narrow OTHER_PKGS inventory.
    local extra_pending=0 extra_ev='' rn rv rr
    if [[ $item == 'OTHER SOFTWARES' && $PKG_KIND == rpm && $RPM_CHECK_OK == 1 ]]; then
        while IFS=$'\t' read -r rn rv rr; do
            [[ -n $rn ]] || continue
            # Web/database/PHP packages have their own audit items. Everything else
            # returned by the successful repository query is relevant here.
            if [[ $rn =~ ^(sw-nginx|nginx|apache2|httpd|litespeed|openlitespeed|lsws)(-|$) ]] ||
               [[ $rn =~ ^([Mm][Yy][Ss][Qq][Ll]|mysql-community|mariadb|MariaDB|postgresql|percona|Percona|redis|mongodb)(-|$) ]] ||
               [[ $rn =~ ^(ea-php|alt-php|php)(-|[0-9]|$) ]]; then
                continue
            fi
            # Do not double count candidates already matched in the normal inventory loop.
            if printf '%s\n' "$inventory" | awk -F '\t' -v p="$rn" '$1==p{found=1} END{exit(found?0:1)}'; then
                continue
            fi
            ((extra_pending++)); extra_ev+="$rn repository-candidate=$rv${rr:+ repo=$rr}; "
        done <<< "$RPM_UPDATES"
        if (( extra_pending > 0 )); then
            pending=$((pending+extra_pending)); ev+="Additional system/repository updates: $extra_ev"
        fi
    fi
    local status=NA
    (( pending > 0 )) && status='Updates pending to install'
    (( count > 0 && pending == 0 && unknown == 0 )) && status='All updates installed'
    ev=$(printf '%s' "$ev" | cut -c1-3600)
    emit "$item" "$status" "Packages=$count; pending=$pending; unverified=$unknown; additional-system-candidates=$extra_pending. $ev Binary evidence: ${binaries:-not collected}. $RPM_CHECK_NOTE Debian cache age=$APT_AGE days. OTHER SOFTWARES additionally evaluates uncategorized/system-wide RPM candidates from the successful repository query; source/container builds remain separate." "$OFFPEAK"
}
version_le() {
    [[ $1 =~ ^[0-9]+(\.[0-9]+){1,3}$ && $2 =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || return 2
    [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1) == "$1" ]]
}
php_eol() {
    local ver=$1 branch=${1%.*} key="php:${1%.*}" end=${BL_EOL["php:${1%.*}"]:-}
    if [[ -z $end || $end == - ]]; then
        case "$branch" in
            5.*|7.*|8.0|8.1) printf 'End Of Life Period'; return;;
            8.2) end=2026-12-31;; 8.3) end=2027-12-31;; 8.4) end=2028-12-31;; 8.5) end=2029-12-31;;
            *) printf NA; return;;
        esac
    fi
    if [[ $TODAY > $end ]]; then printf 'End Of Life Period'; else printf 'Support Period Active'; fi
}
section 'B : Software Updates'
panel_key="panel:plesk:$PANEL_VER"; panel_latest=${BL_LATEST[$panel_key]:-}; panel_status=NA
if [[ -n $panel_latest && $panel_latest != - && $PANEL_VER != "$panel_latest" ]] && version_le "$PANEL_VER" "$panel_latest"; then
    panel_status='Updates pending to install'
fi
emit 'CONTROL PANEL' "$panel_status" "Plesk version=$PANEL_VER; raw build=$PANEL_VERSION_RAW; reviewed release=${panel_latest:-unknown}. $PANEL_REFERENCE_NOTE Matching release numbers do not prove microupdate currency." "$OFFPEAK Verify Tools & Settings > Updates and the applicable Plesk release channel/microupdates."

kernel_pkgs=$(pkgmatch '^(kernel|linux-image|linux-headers)([-:]|$)')
os_update_status=NA; kernel_updates=''; os_repo_candidates=''
if [[ $PKG_KIND == rpm ]]; then
    os_repo_candidates=$(printf '%s\n' "$RPM_UPDATES" | awk -F '\t' '$1 ~ /^(kernel|cloudlinux-release|almalinux-release|rocky-release|centos-release|redhat-release)(-|$)/ {print $1 " -> " $2}' | flat)
    if [[ -n $os_repo_candidates ]]; then
        os_update_status='Updates pending to install'; kernel_updates=$os_repo_candidates
    elif (( RPM_CHECK_OK )); then
        os_update_status='All updates installed'
    fi
fi
while IFS=$'\t' read -r name ver; do
    [[ -n $name ]] || continue
    candidate=$(printf '%s\n' "$APT_CANDIDATES" | awk -F '\t' -v p="$name" '$1==p{print $2;exit}')
    if [[ $PKG_KIND == deb && -n $candidate && $candidate != '(none)' ]] && run dpkg --compare-versions "$ver" lt "$candidate"; then
        os_update_status='Updates pending to install'; kernel_updates+="$name candidate=$candidate; "
    elif [[ $PKG_KIND == deb && $APT_OK == 1 && -n $candidate && $candidate != '(none)' && $os_update_status == NA ]]; then
        os_update_status='All updates installed'
    fi
done <<< "$kernel_pkgs"
# If the installed branch is past standard support and the repository check reports
# no in-branch update candidate, retain the requested update status while clearly
# separating the required OS migration in ISSUE/RECOMMENDATION and Section D.
if (( OS_STANDARD_EOL )) && [[ $os_update_status == "All updates installed" ]]; then
    os_update_status='All updates installed'
    kernel_updates+='Installed OS branch is past standard support; no in-branch release/kernel update candidate was reported. Migration is a separate action. '
fi
vendor_compare_note="$OS_VENDOR_REFERENCE_NOTE"
if [[ -n $OS_VENDOR_LATEST ]]; then
    installed_major=${OS_VERSION%%.*}; vendor_major=${OS_VENDOR_LATEST%%.*}
    if [[ $installed_major =~ ^[0-9]+$ && $vendor_major =~ ^[0-9]+$ && $vendor_major -gt $installed_major ]]; then
        vendor_compare_note+=" Newer major OS branch=$OS_VENDOR_LATEST is available; this requires migration/major upgrade, not a normal package update."
    elif [[ $OS_VENDOR_LATEST == *.* && $OS_VERSION == "$installed_major".* ]] && version_le "$OS_VERSION" "$OS_VENDOR_LATEST" && [[ $OS_VERSION != "$OS_VENDOR_LATEST" ]]; then
        os_update_status='Updates pending to install'
        vendor_compare_note+=" Installed release=$OS_VERSION is older than vendor release reference=$OS_VENDOR_LATEST."
    fi
fi
emit 'OPERATING SYSTEM' "$os_update_status" "OS=$OS_NAME; running kernel=$KERNEL; installed kernels: $(printf '%s' "$kernel_pkgs" | flat). In-branch candidates: ${kernel_updates:-none confirmed}. $RPM_CHECK_NOTE Debian cache age=$APT_AGE days. $vendor_compare_note Vendor URL=${OS_VENDOR_REFERENCE_URL:-not selected}. Standard-EOL=$OS_STANDARD_EOL." "$OFFPEAK"
php_ev=''; php_pending=0; php_unknown=0; php_count=0
while IFS=$'\t' read -r ver bin; do
    [[ -n $ver ]] || continue; ((php_count++)); state=$(php_eol "$ver"); latest=${BL_LATEST["php:${ver%.*}"]:-${PHP_LIVE_LATEST[${ver%.*}]:-}}
    php_ev+="$bin=$ver ($state upstream); "
    if [[ $state == 'End Of Life Period' && $bin == /opt/plesk/php/* ]]; then
        ((php_pending++)); php_ev+='Plesk PHP upstream-EOL branch: supported-version migration required, not proof of a queued RPM update; '
    elif [[ -n $latest && $latest != - && $latest == "$ver" ]]; then :
    elif [[ -n $latest && $latest != - ]] && version_le "$ver" "$latest"; then ((php_pending++)); php_ev+="reviewed branch latest=$latest; "
    else ((php_unknown++)); fi
done <<< "$PHP_LIST"
php_status=NA; (( php_pending>0 )) && php_status='Updates pending to install'
(( php_count>0 && php_pending==0 && php_unknown==0 )) && php_status='All updates installed'
emit PHP "$php_status" "${php_ev:-No CLI PHP version found.} Package inventory: $(pkgmatch '(^php|php[0-9]|plesk-php|alt-php)' | head -n 30 | flat). Plesk registered handlers: $PLESK_HANDLERS. CLI discovery does not prove active FPM/vhost usage; version currency requires a reviewed baseline." "Map each site to its actual PHP handler, review deprecated branches and vendor backports. $OFFPEAK"
cms_ev=''; cms_pending=0; cms_unknown=$CMS_PARTIAL; cms_count=0
while IFS=$'\t' read -r product ver file; do
    [[ -n $product ]] || continue; ((cms_count++)); branch=$(printf '%s' "$ver" | cut -d. -f1-2); key="cms:$product:$branch"; latest=${BL_LATEST[$key]:-}
    [[ $product == wordpress && -z $latest ]] && latest=$WP_LATEST
    cms_ev+="$product $ver at $file; "
    if [[ $product == joomla && $ver == 3.* ]]; then ((cms_pending++)); cms_ev+='Joomla 3 requires migration from the retired branch; '
    elif [[ $product == wordpress && -z $latest ]] && version_le "$ver" 4.6.99; then ((cms_pending++)); cms_ev+='Retired WordPress branch requires upgrade; '
    elif [[ -n $latest && $latest != - && $ver == "$latest" ]]; then :
    elif [[ -n $latest && $latest != - ]] && version_le "$ver" "$latest"; then ((cms_pending++)); cms_ev+="reviewed latest=$latest; "
    else ((cms_unknown++)); fi
done <<< "$CMS_LIST"
cms_status=NA
(( cms_pending>0 || REPORT_CMS_COUNT>0 )) && cms_status='Updates pending to install'
(( cms_count>0 && cms_pending==0 && cms_unknown==0 && REPORT_CMS_COUNT==0 )) && cms_status='All updates installed'
cms_ev=$(printf '%s' "$cms_ev" | cut -c1-3000)
emit CMS "$cms_status" "Filesystem-discovered=$cms_count; discovery needing upgrade/migration=$cms_pending; discovery currency unverified=$cms_unknown. Outdated CMS Report entries=$REPORT_CMS_COUNT; report section present=$REPORT_CMS_SECTION_PRESENT. $WP_REFERENCE_NOTE Filesystem examples (limited): ${cms_ev:-none}. Report examples (limited): ${REPORT_CMS_EXAMPLES:-none}. Scope=$CMS_SCOPE partial=$CMS_PARTIAL. Report and filesystem paths may include staging/backup/trash/old locations; public exposure is NOT inferred from the path alone. $REPORT_INFO Plugins/themes are outside this read-only check unless the supplied report identifies them." "$OFFPEAK"
package_updates 'WEB SERVER' "$WEB_PKGS" "$WEB_BINARIES"
package_updates 'DATABASE SERVER' "$DB_PKGS" "$DB_BINARIES"
package_updates 'OTHER SOFTWARES' "$OTHER_PKGS"

section 'C : Server Health'
uptime_seconds=$(awk '{printf "%.0f",$1}' /proc/uptime 2>/dev/null)
if [[ $uptime_seconds =~ ^[0-9]+$ ]] && (( uptime_seconds>=3600 )); then up_status=GOOD; else up_status='NOT GOOD'; fi
emit 'SERVER UPTIME' "$up_status" "Current uptime=${uptime_seconds:-unknown} seconds; minimum=3600. This measures time since boot, not historical reliability." 'Review recent reboot reasons if under one hour; correlate with authorized maintenance and monitoring history.'
http_status='NOT GOOD'; http_ev=''; web_running=0; web_bad=0
declare -A HTTP_SEEN
for svc in nginx apache2 httpd lsws litespeed; do
    if active "$svc"; then
        service_age=''; service_key=''; main_pid=''
        if have systemctl && [[ -d /run/systemd/system ]]; then
            properties=$(run systemctl show "$svc" -p Id -p MainPID -p ActiveState -p ActiveEnterTimestampMonotonic)
            start=$(printf '%s\n' "$properties" | sed -n 's/^ActiveEnterTimestampMonotonic=//p')
            main_pid=$(printf '%s\n' "$properties" | sed -n 's/^MainPID=//p')
            unit_id=$(printf '%s\n' "$properties" | sed -n 's/^Id=//p')
            if printf '%s\n' "$properties" | grep -Fxq 'ActiveState=active' && [[ $start =~ ^[0-9]+$ && $uptime_seconds =~ ^[0-9]+$ ]] && (( start>0 )); then
                service_age=$((uptime_seconds-start/1000000)); service_key="unit:$unit_id"
                [[ $main_pid =~ ^[1-9][0-9]*$ ]] && service_key="pid:$main_pid"
            fi
        fi
        if [[ -z $service_age ]] && have ps; then
            read -r process_pid process_age < <(run ps -C "$svc" -o pid=,etimes= | sort -k2,2nr | head -n 1)
            if [[ $process_pid =~ ^[0-9]+$ && $process_age =~ ^[0-9]+$ ]]; then service_key="pid:$process_pid"; service_age=$process_age; fi
        fi
        [[ -n $service_key ]] || service_key="unverified:$svc"
        [[ -n ${HTTP_SEEN[$service_key]:-} ]] && continue; HTTP_SEEN[$service_key]=1
        ((web_running++))
        if [[ $service_age =~ ^[0-9]+$ ]] && (( service_age>=3600 )); then http_ev+="$svc uptime=$service_age seconds ($service_key); "
        else ((web_bad++)); http_ev+="$svc running; age=${service_age:-unverified} seconds ($service_key); "; fi
    fi
done
(( web_running>0 && web_bad==0 )) && http_status=GOOD
for url in "${HTTP_URLS[@]}"; do
    if (( OFFLINE )) || ! have curl; then http_ev+='Requested HTTP check skipped (offline/curl unavailable); '; http_status='NOT GOOD'; continue; fi
    # -q ignores curlrc; no redirects, cookies, credentials or response body stored.
    code=$(run curl -q --noproxy '*' --proto '=http,https' --connect-timeout 4 --max-time 10 -sS -I -o /dev/null -w '%{http_code}' -- "$url"); curl_rc=$?
    if (( curl_rc==0 )) && [[ $code =~ ^[23][0-9][0-9]$ ]]; then http_ev+="Requested endpoint returned HTTP $code; "
    else http_ev+="Requested endpoint failed/unhealthy or HEAD unsupported (curl=$curl_rc HTTP=$code); "; http_status='NOT GOOD'; fi
done
emit 'HTTP UPTIME' "$http_status" "${http_ev:-No supported running local web service confirmed.} Current service age is not historical HTTP availability; ${#HTTP_URLS[@]} explicit URL(s)." 'Review external uptime history and critical virtual hosts. Use --http-url for known safe health endpoints; no default website requests are made.'
cpu_sample() { awk '/^cpu / {total=0;for(i=2;i<=9;i++)total+=$i;print total,$5+$6;exit}' /proc/stat; }
read -r total1 idle1 < <(cpu_sample); sleep 2; read -r total2 idle2 < <(cpu_sample)
cores=$(awk '/^processor[[:space:]]*:/{n++} END{print n+0}' /proc/cpuinfo)
load1=$(awk '{print $1}' /proc/loadavg)
cpu_busy='unknown'; cpu_status='NOT GOOD'; load_pct='unknown'
if [[ $total1 =~ ^[0-9]+$ && $total2 =~ ^[0-9]+$ ]] && (( total2>total1 && cores>0 )); then
    cpu_busy=$((100*(total2-total1-idle2+idle1)/(total2-total1)))
    load_pct=$(awk -v l="$load1" -v n="$cores" 'BEGIN{printf "%.0f",100*l/n}')
    (( cpu_busy<CPU_MAX && load_pct<CPU_MAX )) && cpu_status=GOOD
fi
emit 'CPU USAGE' "$cpu_status" "Two-second busy=$cpu_busy%; 1-minute load=$load1; cores=$cores; load/core=$load_pct%; threshold=$CPU_MAX%. Load includes uninterruptible waits." 'Correlate sustained load, CPU steal and I/O wait with monitoring; a short sample can miss spikes.'
read -r mem_total mem_avail mem_method < <(awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2;has=1}/^MemFree:/{f=$2}/^Buffers:/{b=$2}/^Cached:/{c=$2}/^SReclaimable:/{r=$2}/^Shmem:/{s=$2} END{if(has)print t,a,"MemAvailable";else print t,f+b+c+r-s,"estimated"}' /proc/meminfo)
ram_status='NOT GOOD'; ram_used=unknown
if [[ $mem_total =~ ^[0-9]+$ && $mem_avail =~ ^[0-9]+$ ]] && (( mem_total>0 && mem_avail<=mem_total )); then
    ram_used=$((100*(mem_total-mem_avail)/mem_total)); (( ram_used<RAM_MAX )) && ram_status=GOOD
fi
swap_ev=$(awk '/^SwapTotal:/{t=$2}/^SwapFree:/{f=$2} END{printf "swap-used=%d KiB of %d KiB",t-f,t}' /proc/meminfo)
emit 'RAM USAGE' "$ram_status" "Used excluding available cache=$ram_used%; threshold=$RAM_MAX%; method=$mem_method; $swap_ev." 'Review sustained memory pressure, swap activity and OOM events before changing memory allocations.'
disk_status=GOOD; disk_ev=''; dfout=$(run df -P -l -k); dfrc=$?; inodeout=$(run df -P -l -i); ifrc=$?
if (( dfrc!=0 || ifrc!=0 )); then disk_status='NOT GOOD'; disk_ev+='UNVERIFIED: filesystem statistics failed; '; fi
disk_bad=$(printf '%s\n' "$dfout" | awk -v max="$DISK_MAX" 'NR>1 {v=$5;gsub(/%/,"",v);if(v+0>=max)print $1 " " $5 " " $6}')
inode_bad=$(printf '%s\n' "$inodeout" | awk -v max="$DISK_MAX" 'NR>1 {v=$5;gsub(/%/,"",v);if(v ~ /^[0-9]+$/ && v+0>=max)print $1 " " $5 " " $6}')
[[ -n $disk_bad || -n $inode_bad ]] && disk_status='NOT GOOD'
disk_ev+="Local filesystem threshold=$DISK_MAX%. Space alerts: ${disk_bad:-none}. Inode alerts: ${inode_bad:-none}. Remote filesystems excluded to avoid stalled network mounts."
emit 'DISC SPACE USAGE' "$disk_status" "$disk_ev" 'Review growth and inode use on alerted mounts; obtain developer approval before removing application files. Review remote mount capacity separately.'
queue_status='NOT GOOD'; queue_ev='UNVERIFIED: no supported readable mail queue.'; queue_total=0; queue_seen=0; queue_unknown=0
if have exim; then
    q=$(run exim -bpc)
    if [[ $q =~ ^[0-9]+$ ]]; then ((queue_seen++)); ((queue_total+=q)); queue_ev="Exim messages=$q; "; else ((queue_unknown++)); fi
fi
if have postqueue; then
    qout=$(run postqueue -p); qrc=$?; q=''
    if (( qrc==0 )); then
        if [[ $qout == *'Mail queue is empty'* ]]; then q=0
        else q=$(printf '%s\n' "$qout" | sed -nE 's/^-- .* in ([0-9]+) Request(s)?\..*/\1/p' | tail -n 1); fi
    fi
    if [[ $q =~ ^[0-9]+$ ]]; then ((queue_seen++)); ((queue_total+=q)); queue_ev+="Postfix messages=$q; "; else ((queue_unknown++)); fi
fi
(( queue_seen>0 && queue_unknown==0 && queue_total<=QUEUE_MAX )) && queue_status=GOOD
emit 'EMAIL QUEUE' "$queue_status" "$queue_ev Total confirmed=$queue_total; threshold=$QUEUE_MAX; unreadable queues=$queue_unknown. Sendmail/other MTAs need manual review; no message content printed." 'Inspect queue age, deferrals, delivery rates and legitimate traffic volume. Do not delete or flush messages without approval.'

dns_query() { run dig +time=3 +tries=1 +noall +comments +answer "$@"; }
dns_code() { sed -nE 's/.*status: ([A-Z]+),.*/\1/p' | head -n 1; }
dns_a() { awk '$4=="A" {print $5}'; }
reputation_status='NOT GOOD'; reputation_ev='UNVERIFIED: requires a selected public IPv4, dig and network access.'
REPUTATION_LISTS=''; dns_listed=0; dns_clean=0; dns_unknown=0
if (( ! OFFLINE )) && [[ -n $TARGET_IP ]] && have dig; then
    IFS=. read -r a b c d <<< "$TARGET_IP"; reverse="$d.$c.$b.$a"
    reputation_ev=''
    # Active DNSBL checks only. SORBS was decommissioned in 2024 and is intentionally not queried.
    for zone in zen.spamhaus.org bl.spamcop.net b.barracudacentral.org; do
        provider=$zone; expected='^127\.0\.0\.2$'
        case "$zone" in
            zen.spamhaus.org) provider=Spamhaus; expected='^127\.0\.0\.(2|3|4|9|10|11)$';;
            bl.spamcop.net) provider=SpamCop;;
            b.barracudacentral.org) provider=Barracuda;;
        esac
        pos=$(dns_query "2.0.0.127.$zone" A); neg=$(dns_query "1.0.0.127.$zone" A)
        pos_codes=$(printf '%s\n' "$pos" | dns_a); neg_status=$(printf '%s\n' "$neg" | dns_code)
        if ! printf '%s\n' "$pos_codes" | grep -Eq "$expected" ||
           printf '%s\n' "$pos_codes" | grep -Eq '^127\.255\.255\.' || [[ $neg_status != NXDOMAIN ]]; then
            ((dns_unknown++)); reputation_ev+="$provider query controls failed/blocked; "; continue
        fi
        ans=$(dns_query "$reverse.$zone" A); code=$(printf '%s\n' "$ans" | dns_code); codes=$(printf '%s\n' "$ans" | dns_a)
        if [[ $code == NXDOMAIN ]]; then
            ((dns_clean++)); reputation_ev+="$provider not listed; "
        elif [[ $code == NOERROR ]] && [[ -n $codes ]]; then
            valid=1
            while read -r answer; do printf '%s\n' "$answer" | grep -Eq "$expected" || valid=0; done <<< "$codes"
            if (( valid )); then
                ((dns_listed++)); reputation_ev+="$provider LISTED ($codes); "
                [[ -n $REPUTATION_LISTS ]] && REPUTATION_LISTS+=', '
                REPUTATION_LISTS+="$provider"
            else
                ((dns_unknown++)); reputation_ev+="$provider provider error/unrecognized response ($codes); "
            fi
        else
            ((dns_unknown++)); reputation_ev+="$provider DNS response unverified ($code); "
        fi
    done
    (( dns_listed==0 && dns_unknown==0 && dns_clean==3 )) && reputation_status=GOOD
    reputation_ev+="IP=$TARGET_IP; listed=$dns_listed not-listed=$dns_clean unverified=$dns_unknown. Active checks: Spamhaus, SpamCop and Barracuda. SORBS is retired and not queried. A policy listing is not by itself proof of compromise."
fi
if (( IP_MISMATCH )); then reputation_status='NOT GOOD'; reputation_ev+=" OWNERSHIP UNVERIFIED: $IP_NOTE"; fi
emit 'IP REPUTATION' "$reputation_status" "$reputation_ev" 'Confirm actual outbound SMTP IP and investigate any confirmed listing before requesting delisting.'

section 'D : Software Life Time'
panel_end=${BL_EOL[$panel_key]:-}; panel_life=NA; panel_life_note=''
if [[ -n $panel_end && $panel_end != - ]]; then
    if [[ $TODAY > $panel_end ]]; then panel_life='End Of Life Period'; else panel_life='Support Period Active'; fi
fi
emit 'CONTROL PANEL' "$panel_life" "Panel=$PANEL version=${PANEL_VER:-none}; reviewed/support reference=${panel_end:-unknown}. $panel_life_note $PANEL_REFERENCE_NOTE" "Check vendor support policy if a panel is present. $OFFPEAK"
os_life=NA; os_end=${BL_EOL["os:$OS_ID:$OS_VERSION"]:-}; os_note='Vendor support and entitlement unverified.'
if [[ -n $os_end && $os_end != - ]]; then
    if [[ $TODAY > $os_end ]]; then os_life='End Of Life Period'; else os_life='Support Period Active'; fi
    os_note="Reviewed standard/vendor support end=$os_end."
elif [[ $OS_ID == cloudlinux || $OS_NAME == CloudLinux* ]]; then
    case "$OS_VERSION" in
        7|7.*) os_end=2024-06-30;; 8|8.*) os_end=2029-05-31;;
        9|9.*) os_end=2032-05-31;; 10|10.*) os_end=2035-05-31;;
    esac
    if [[ -n $os_end && $os_end != - ]]; then
        if [[ $TODAY > $os_end ]]; then os_life='End Of Life Period'; else os_life='Support Period Active'; fi
        os_note="CloudLinux vendor branch lifecycle end=$os_end. License/subscription, optional ELS and package patch currency are separate checks."
    fi
elif [[ $OS_ID == centos && $OS_NAME != *Stream* ]]; then
    case "$OS_VERSION" in 7|7.*) os_life='End Of Life Period'; os_note='CentOS Linux 7 upstream support ended 2024-06-30.';;
        8|8.*) os_life='End Of Life Period'; os_note='CentOS Linux 8 upstream support ended 2021-12-31.';; esac
elif [[ $OS_ID == ubuntu ]]; then
    end_month=''
    case "$OS_VERSION" in
        14.04) end_month=2019-04;; 16.04) end_month=2021-04;; 18.04) end_month=2023-05;;
        20.04) end_month=2025-05;; 22.04) end_month=2027-05;; 24.04) end_month=2029-05;; 26.04) end_month=2031-05;;
    esac
    if [[ -n $end_month ]]; then
        os_note="Ubuntu standard security maintenance ends in $end_month; Pro/ESM entitlement and package coverage unverified."
        if [[ ${TODAY:0:7} > $end_month ]]; then os_life='End Of Life Period'
        elif [[ ${TODAY:0:7} < $end_month ]]; then os_life='Support Period Active'
        else os_note+=' Exact transition date requires verification this month.'; fi
    fi
elif [[ $OS_ID == almalinux || $OS_ID == rocky || $OS_ID == debian ]]; then
    os_note='Exact installed release lifecycle unverified without a reviewed baseline; no latest minor release inferred.'

fi
[[ $KERNEL == *tuxcare* || $KERNEL == *els* ]] && os_note+=' Extended-support kernel marker detected; this does not prove a current subscription, patch level or userspace coverage.'
emit 'OPERATING SYSTEM' "$os_life" "$OS_NAME. $os_note $OS_VENDOR_REFERENCE_NOTE Vendor URL=${OS_VENDOR_REFERENCE_URL:-not selected}." "Verify vendor lifecycle and paid extended-support entitlement. Plan supported-OS migration where appropriate. $OFFPEAK"
cms_life=NA; cms_eol=0; cms_supported=0; cms_life_unknown=$CMS_PARTIAL
while IFS=$'\t' read -r product ver file; do
    [[ -n $product ]] || continue; branch=$(printf '%s' "$ver" | cut -d. -f1-2); end=${BL_EOL["cms:$product:$branch"]:-}
    if [[ -n $end && $end != - ]]; then
        if [[ $TODAY > $end ]]; then ((cms_eol++)); else ((cms_supported++)); fi
    elif [[ $product == joomla && $ver == 3.* ]]; then ((cms_eol++))
    elif [[ $product == wordpress && -n $WP_LATEST ]]; then
        if [[ $ver == "$WP_LATEST" ]]; then ((cms_supported++)); else ((cms_life_unknown++)); fi
    elif [[ $product == wordpress ]] && version_le "$ver" 4.6.99; then ((cms_eol++))
    else ((cms_life_unknown++)); fi
done <<< "$CMS_LIST"
(( cms_eol>0 )) && cms_life='End Of Life Period'
(( cms_count>0 && cms_eol==0 && cms_life_unknown==0 && REPORT_CMS_COUNT==0 )) && cms_life='Support Period Active'
emit CMS "$cms_life" "Filesystem-detected CMS=$cms_count; unsupported branches=$cms_eol supported-branch=$cms_supported unverified=$cms_life_unknown. Outdated CMS Report entries=$REPORT_CMS_COUNT (outdated alone does not prove EOL); report examples=${REPORT_CMS_EXAMPLES:-none}. $WP_REFERENCE_NOTE Report/filesystem paths can include inactive backups, staging or trash and require exposure review. $REPORT_INFO" "$OFFPEAK"
stack_life=NA; stack_ev=''; stack_eol=0; stack_unknown=0; stack_seen=0
while IFS=$'\t' read -r ver bin; do
    [[ -n $ver ]] || continue; ((stack_seen++)); state=$(php_eol "$ver"); stack_ev+="PHP $ver: $state upstream; "
    [[ $state == 'End Of Life Period' ]] && ((stack_eol++)); [[ $state == NA ]] && ((stack_unknown++))
done <<< "$PHP_LIST"
while IFS=$'\t' read -r name ver; do
    [[ -n $name ]] || continue; ((stack_seen++)); end=${BL_EOL["pkg:$name"]:-}
    if [[ -z $end || $end == - ]]; then ((stack_unknown++))
    elif [[ $TODAY > $end ]]; then ((stack_eol++)); stack_ev+="$name support ended $end; "; fi
done < <(printf '%s\n%s\n%s\n' "$WEB_PKGS" "$DB_PKGS" "$OTHER_PKGS" | sort -u)
(( stack_eol>0 )) && stack_life='End Of Life Period'
(( stack_seen>0 && stack_unknown==0 && stack_eol==0 )) && stack_life='Support Period Active'
emit 'SOFTWARE STACK' "$stack_life" "$stack_ev Unverified component lifecycles=$stack_unknown. Upstream PHP EOL can differ from contracted distro/CloudLinux/TuxCare backport support; no entitlement inferred." "Confirm support for actual web, PHP, database, mail and DNS stack, including custom builds and vendor backports. $OFFPEAK"

section 'E : Proactive Defence'
tmp_status='Not Configured'; tmp_ev='UNVERIFIED: /tmp mount options unavailable.'
if have findmnt; then
    opts=$(run findmnt -n -T /tmp -o OPTIONS); perms=$(stat -c %a /tmp 2>/dev/null)
    tmp_ev="Effective /tmp mount options=$opts; permissions=$perms."
    if [[ ,$opts, == *,noexec,* && ,$opts, == *,nosuid,* && ,$opts, == *,nodev,* && $perms == 1777 ]]; then tmp_status=Configured; fi
fi
emit '/tmp SECURITY' "$tmp_status" "$tmp_ev noexec does not prevent an interpreter from reading a script in /tmp." 'Review noexec,nosuid,nodev and sticky permissions with application owners; also review /var/tmp and /dev/shm. No mount or permission changes were made.'
emit 'REBOOT PROCEDURE' 'Manual verification required' 'Remote reboot portal/datacenter login details and reboot procedure cannot be verified from local server evidence.' 'Request the datacenter/reboot details securely.'
rdns_status='Not Configured'; rdns_ev='UNVERIFIED: requires public IPv4, dig and network access.'
if (( ! OFFLINE )) && [[ -n $TARGET_IP ]] && have dig; then
    ptrout=$(dns_query -x "$TARGET_IP"); ptr_status=$(printf '%s\n' "$ptrout" | dns_code)
    ptrs=$(printf '%s\n' "$ptrout" | awk '$4=="PTR"{print $5}')
    rdns_ev="IP=$TARGET_IP; PTR status=$ptr_status; records=${ptrs:-none}. "
    while read -r ptr; do
        [[ $ptr =~ ^[A-Za-z0-9_.-]+\.$ ]] || continue
        forward=$(dns_query "$ptr" A | dns_a)
        if printf '%s\n' "$forward" | grep -Fxq "$TARGET_IP"; then rdns_status=Configured; rdns_ev+='Forward-confirmed PTR found; '; fi
    done <<< "$ptrs"
fi
if (( IP_MISMATCH )); then rdns_status='Not Configured'; rdns_ev+=" OWNERSHIP UNVERIFIED: $IP_NOTE"; fi
emit 'IP RDNS' "$rdns_status" "$rdns_ev" 'Set PTR through the IP provider and confirm its forward A record matches the mail egress IP and SMTP hostname; PTR alone does not guarantee delivery.'
for kind in MALWARE ROOTKIT; do
    result=$MALWARE_RESULT; item='MALWARE SCAN'
    if [[ $kind == MALWARE ]]; then
        evidence="Bobcares Malware Scan Report section present=$REPORT_MALWARE_SECTION_PRESENT; findings=$REPORT_MALWARE_COUNT; files=$REPORT_MALWARE_FILE_COUNT; examples=${REPORT_MALWARE_EXAMPLES:-none}."
    else
        result=$ROOTKIT_RESULT; item='ROOTKIT CHECK'; evidence="Bobcares Rootkit Scan Report section present=$REPORT_ROOTKIT_SECTION_PRESENT; $ROOTKIT_EVIDENCE"
    fi
    case "$result" in
        clean) status=Configured; issue="Recent $kind report result is clean/zero findings. $evidence $REPORT_INFO Report scope/authenticity still require review; this is not proof of absence of compromise.";;
        found) status='Not Configured'; issue="$kind findings are reported. $evidence $REPORT_INFO Findings require investigation; nothing was removed, modified or rescanned by this audit.";;
        *) status='MALWARE SCAN NEEDED'; issue="$kind result is unverified: missing, stale, incomplete or unrecognized report evidence. $evidence $REPORT_INFO";;
    esac
    emit "$item" "$status" "$issue" 'Review the existing report, scope, timestamps and findings. Arrange a separately approved scan if evidence is missing or inconclusive; this audit never scans or cleans files.'
done
ssh_status='Not Configured'; ssh_ev='UNVERIFIED: effective OpenSSH configuration unavailable.'
if have sshd; then
    sshcfg=$(run sshd -T); sshrc=$?; rootlogin=$(printf '%s\n' "$sshcfg" | awk '$1=="permitrootlogin"{print $2}')
    matchfiles=''
    for dir in /etc/ssh/sshd_config /etc/ssh/sshd_config.d; do
        [[ -e $dir ]] || continue
        matchfiles+=$(run grep -rIlE '^[[:space:]]*(Match|Include)[[:space:]]' "$dir")
    done
    ssh_ev="sshd -T PermitRootLogin=${rootlogin:-unknown}. Conditional/include configuration candidates=${matchfiles:-none found}."
    if (( sshrc==0 )) && [[ $rootlogin == no && -z $matchfiles ]]; then ssh_status=Configured
    else ssh_ev+=' Match/Include contexts and nonstandard sshd launch options require manual effective-config checks; prohibit-password still permits root keys.'; fi
fi
emit 'SSH ROOT ACCESS SECURITY' "$ssh_status" "$ssh_ev" 'Review effective sshd settings for each Match context and actual daemon config path. If changing access, first verify a named sudo account and recovery access; this script changes nothing.'
php_config_ev=''; php_configs=0; php_insecure_configs=0; php_secure_configs=0
DANGEROUS_PHP_FUNCTIONS='exec passthru shell_exec system proc_open popen'
for file in /etc/php.ini /etc/php.d/*.ini /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php/*/cli/php.ini /opt/remi/php*/root/etc/php.ini /opt/alt/php*/etc/php.ini /opt/plesk/php/*/etc/php.ini "$PLESK_VHOSTS"/system/*/etc/php.ini; do
    [[ -f $file && -r $file ]] || continue; ((php_configs++))
    values=$(awk -F= '/^[[:space:]]*disable_functions[[:space:]]*=/ {v=substr($0,index($0,"=")+1);sub(/[;#].*/,"",v);print v}' "$file" | tail -n 1)
    normalized=$(printf '%s' "$values" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    enabled=''
    for fn in $DANGEROUS_PHP_FUNCTIONS; do
        if [[ ,$normalized, != *,$fn,* ]]; then enabled+="$fn,"; fi
    done
    enabled=${enabled%,}
    if [[ -n $enabled ]]; then
        ((php_insecure_configs++)); php_config_ev+="$file enabled/unrestricted selected functions=$enabled; "
    else
        ((php_secure_configs++)); php_config_ev+="$file selected dangerous functions disabled; "
    fi
done
php_sec=NA
if (( php_configs > 0 )); then
    if (( php_insecure_configs > 0 )); then php_sec='Not Configured'
    elif (( php_secure_configs == php_configs )); then php_sec=NA
    fi
fi
emit 'PHP FUNCTIONS SECURITY' "$php_sec" "Inspected INI candidates=$php_configs; candidates with selected dangerous functions enabled/unrestricted=$php_insecure_configs; fully restricted candidates=$php_secure_configs. ${php_config_ev:-No conventional PHP INI files found.} Selected functions=$DANGEROUS_PHP_FUNCTIONS. UNVERIFIED effective PHP-FPM/pool/per-site/container overrides can differ and require developer review; disable_functions is defense-in-depth, not a complete security boundary." 'Review required restrictions with developers; do not disable functions blindly.'

pw_status='Not Configured'; pw_ev='UNVERIFIED root password age.'
if [[ -r /etc/shadow ]]; then
    # Emit only last-change day and lock classification, never password hashes.
    read -r changed lockstate < <(awk -F: '$1=="root" {s=($2 ~ /^[!*]/ ? "locked" : ($2==""?"empty":"set"));print $3,s;exit}' /etc/shadow)
    if [[ $changed =~ ^[0-9]+$ ]]; then
        pw_age=$((NOW/86400-changed)); pw_ev="Root password last-change age=$pw_age days; password state=$lockstate."
        if [[ $lockstate == locked ]]; then pw_status=NA; pw_ev+=' Password login is locked; this does not disable root SSH keys.'
        elif [[ $lockstate == set ]] && (( changed>0 && pw_age>=0 && pw_age<=90 )); then pw_status=Configured; fi
    fi
fi
emit 'ROOT PASSWORD HEALTH' "$pw_status" "$pw_ev" 'For password-enabled root, apply the requested 90-day policy through the approved credential process. Review key-only/locked accounts separately; no password hash is displayed.'

section 'F : Backup'
# Only allowlisted scalar fields; never read passwords, remoteStorage or email.
backup_db_ok=0; backup_rows=''; backup_schedule_ev='UNVERIFIED: Plesk schedule query failed/unavailable.'
local_status=NA; remote_status=NA; daily_status=NA; weekly_status=NA; monthly_status=NA
if have plesk; then
    backup_rows=$(run plesk db -Ne 'SELECT id,active,repository,period,full_backup_period,rotation FROM BackupsScheduled WHERE obj_type="server" ORDER BY id'); brc=$?
    if (( brc==0 )); then
        backup_db_ok=1; local_status='Not configured'; remote_status='Not configured'
        daily_status='Not configured'; weekly_status='Not configured'
        backup_schedule_ev='Server-level BackupsScheduled rows only; '
        while IFS=$'\t' read -r bid enabled repository period full_period retention; do
            [[ -n $bid ]] || continue
            if [[ ! $bid =~ ^[0-9]+$ || ! $enabled =~ ^(true|false|1|0)$ || ! $repository =~ ^[A-Za-z_-]+$ || ! $period =~ ^[0-9]+$ || ! $full_period =~ ^[0-9]+$ || ! $retention =~ ^[0-9]+$ ]]; then
                backup_db_ok=0; continue
            fi
            backup_schedule_ev+="task=$bid active=$enabled repository=$repository period=$period full-period=$full_period retention=$retention; "
            [[ $enabled == true || $enabled == 1 ]] || continue
            case "$repository" in
                local) local_status=Configured;;
                ftp|ext) remote_status=Configured; [[ $local_status == Configured ]] || local_status=NA;;
                *) local_status=NA; remote_status=NA;;
            esac
            [[ $period == 86400 ]] && daily_status=Configured
            [[ $period == 604800 ]] && weekly_status=Configured
        done <<< "$backup_rows"
        if (( ! backup_db_ok )); then
            local_status=NA; remote_status=NA; daily_status=NA; weekly_status=NA
            backup_schedule_ev+='UNVERIFIED: unexpected schedule data; '
        fi
    fi
    # Corroborate monthly label without guessing seconds-to-calendar semantics.
    schedule_list=$(run plesk bin scheduled-backup --list -server); slrc=$?
    if (( slrc==0 )); then
        monthly_enabled=$(printf '%s\n' "$schedule_list" | awk 'tolower($1) ~ /^(true|yes|1)$/ && tolower($2)=="monthly"{n++} END{print n+0}')
        (( monthly_enabled>0 )) && monthly_status=Configured
        backup_schedule_ev+="Read-only schedule list exit=$slrc; monthly enabled rows=$monthly_enabled (recognized active/period columns only). "
    fi
    unset schedule_list
fi
backup_schedule_ev+='Configured describes an enabled server-level schedule, not successful execution or all subscription coverage. Remote storage may also retain local copies; separate retention verification required.'

backup_file=''; backup_time=0; backup_size=0; backup_files=0; backup_partial=0; backup_stamp=''; backup_root=''
for root in "${BACKUP_DIRS[@]}"; do
    [[ -d $root ]] || continue
    listing=$(timeout -k 2s 30s find "$root" -xdev -maxdepth 10 -type f -name '*info_*.xml' -printf '%T@\t%p\n' 2>/dev/null); lrc=$?
    (( lrc==0 )) || backup_partial=1
    while IFS=$'\t' read -r mtime candidate; do
        mtime=${mtime%%.*}
        [[ $mtime =~ ^[0-9]+$ && ${candidate##*/} =~ _info_([0-9]{10,14})\.xml$ ]] || continue
        stamp=${BASH_REMATCH[1]}
        if (( mtime>backup_time )); then backup_time=$mtime; backup_file=$candidate; backup_stamp=$stamp; backup_root=$root; fi
    done <<< "$listing"
done
if [[ -n $backup_file ]]; then
    # Candidate set only: dependent incremental chains can span other timestamps.
    sizes=$(timeout -k 2s 30s find "$backup_root" -xdev -maxdepth 10 -type f -name "*${backup_stamp}*" ! -name '*.xml' ! -name '*.log' -printf '%s\n' 2>/dev/null); src=$?
    (( src==0 )) || backup_partial=1
    read -r backup_files backup_size < <(printf '%s\n' "$sizes" | awk '/^[0-9]+$/{n++;s+=$1}END{printf "%d %.0f\n",n+0,s+0}')
fi
backup_age=unknown
(( backup_time>0 && NOW>=backup_time )) && backup_age=$(((NOW-backup_time)/86400))
log_path=''; log_age=unknown; log_errors=unknown; log_warnings=unknown
if [[ -d /var/log/plesk/PMM ]]; then
    logrow=$(timeout -k 2s 15s find /var/log/plesk/PMM -xdev -maxdepth 5 -type f \( -name 'backup.log' -o -name 'psadump.log' \) -printf '%T@\t%p\n' 2>/dev/null | sort -nr | head -n 1)
    logepoch=${logrow%%$'\t'*}; logepoch=${logepoch%%.*}; log_path=${logrow#*$'\t'}
    if [[ -n $log_path && -r $log_path ]]; then
        [[ $logepoch =~ ^[0-9]+$ ]] && (( NOW>=logepoch )) && log_age=$(((NOW-logepoch)/86400))
        logtail=$(run tail -n 2000 "$log_path"); logrc=$?
        if (( logrc==0 )); then
            log_errors=$(printf '%s\n' "$logtail" | grep -Eic 'error|failed|failure' || true)
            log_warnings=$(printf '%s\n' "$logtail" | grep -Eic 'warning|warn' || true)
        fi
        unset logtail
    fi
fi
backup_ev="Newest metadata=${backup_file:-none}; mtime-age=$backup_age days; matching non-XML files=$backup_files; candidate bytes=$backup_size; partial search=$backup_partial. Latest PMM log=${log_path:-not found}; log-age=$log_age days; last-2000-line error markers=$log_errors warning markers=$log_warnings. Log is NOT correlated to candidate or proof of completion; raw logs withheld to avoid exposing secrets."
emit 'LOCAL BACKUP' "$local_status" "$backup_schedule_ev $backup_ev Artifact presence does not establish retained local backup policy." 'Review Plesk Tools & Settings > Backup Manager, retained local storage, exclusions, successful jobs and restore coverage. Also review subscription/customer/reseller schedules and custom backup tools.'
emit 'REMOTE BACKUP' "$remote_status" "$backup_schedule_ev Remote repository configuration was not contacted; credentials were not queried. Independent remote storage settings/extensions may exist outside scheduled rows." 'Verify Remote Storage Settings and the matching successful upload log. Confirm off-server retention, recovery credentials and test restoration separately.'
for frequency in DAILY WEEKLY MONTHLY; do
    case "$frequency" in DAILY) status=$daily_status;; WEEKLY) status=$weekly_status;; MONTHLY) status=$monthly_status;; esac
    emit "$frequency BACKUP" "$status" "$backup_schedule_ev Frequency=$frequency. Daily incremental plus weekly full is not classified as two independent schedules. Unknown calendar labels remain NA." 'Confirm the requested frequency, full/incremental policy, retention, exclusions and latest successful run in Plesk Backup Manager.'
done
recent_status=NA
emit 'RECENT LAST BACKUP' "$recent_status" "$backup_ev Recency threshold=$BACKUP_MAX_DAYS days. UNVERIFIED completion: XML may describe configuration-only/remote data and mtime is not a successful job timestamp." 'Check the corresponding completed Plesk backup and upload logs, required data parts and incremental chain. Manually confirm recent successful backup status before submitting the audit.'
size_status=NA
if (( EXPECTED_BACKUP_BYTES>0 && backup_files>0 && backup_partial==0 )); then
    if (( backup_size<EXPECTED_BACKUP_BYTES )); then size_status='Too small'
    else size_status='Expected size'; fi
fi
emit 'SIZE OF LAST BACKUP' "$size_status" "Metadata=${backup_file:-none}; matching non-XML candidate bytes=$backup_size; files=$backup_files; supplied minimum=$EXPECTED_BACKUP_BYTES; partial search=$backup_partial. Without a supplied minimum, size remains NA. Candidate may exclude required base/incremental parts or combine objects sharing a timestamp; this is not a validated restore-set total." 'Confirm candidate scope and compare it to a matching known-good minimum. Validate required backup parts and restoration separately; size alone cannot prove integrity.'

printf 'Audit complete. No findings were remediated. Review every UNVERIFIED/manual item before submitting the audit.\n'
exit 0
