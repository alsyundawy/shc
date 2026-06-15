#!/usr/bin/env bash
# Audit & Hardening by HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION (2026)
# shellcheck disable=SC2016,SC2028

set -Eeuo pipefail

# Gunakan IFS yang aman
IFS=$'\n\t'

shells=('/bin/sh' '/bin/dash' '/bin/bash' '/bin/ksh' '/bin/zsh' '/usr/bin/tcsh' '/bin/csh' '/usr/bin/rc' '/usr/bin/python' '/usr/bin/python2' '/usr/bin/python3' '/usr/bin/perl')

check_opts=('' '-r' '-v' '-D' '-S' '-P' '-p' '-H' '-2')

shc="${1:-shc}"

txtred='\e[0;31m' # Red
txtgrn='\e[0;32m' # Green
txtrst='\e[0m'    # Text Reset

stat=0
pc=0
fc=0

# Validasi environment SKIP
SKIP="${SKIP:-}"
SKIP=",${SKIP},ash,"

# Variabel penampung tmp dir untuk dibersihkan oleh trap
ACTIVE_TMPD=""

# shellcheck disable=SC2329 # Fungsi ini dipanggil melalui trap, bukan langsung
cleanup() {
    local exit_code=$?
    if [[ -n "${ACTIVE_TMPD}" && -d "${ACTIVE_TMPD}" ]]; then
        # Bersihkan hanya jika exit karena interupsi, bukan karena failure test (stat=1 dipertahankan untuk debug)
        if [[ $exit_code -ne 0 && "${stat}" -eq 0 ]]; then
            rm -rf "${ACTIVE_TMPD}" || true
        fi
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo
echo "== Running tests ... (Skip expression: $SKIP)"
for shell in "${shells[@]}"; do
    BASESHELL="${shell##*/}"
    
    if [[ "${SKIP#*,"${BASESHELL}",}" != "$SKIP" ]] ; then
        echo    "===================================================="
        printf "=== %-20s :SKIPPED\n" "$shell"
        echo    "===================================================="
        continue
    fi
    
    if [[ ! -x "$shell" ]] ; then
        echo    "===================================================="
        printf "=== %-20s :%bMISSING%b\n" "$shell" "${txtred}" "${txtrst}"
        echo    "===================================================="
        fc=$((fc + 1))
        stat=1
        continue
    fi
    
    for opt in "${check_opts[@]}"; do
        if [[ "${opt}" == "-H" ]] ; then
            if [[ "${shell#*sh}" == "$shell" ]] ; then
                # Only supported for "bourne shell"
                continue
            fi
        fi
        
        # Aman menggunakan mktemp dengan prefix XXXXXX
        tmpd=$(mktemp -d "${TMPDIR:-/tmp}/shc.${BASESHELL}${opt}.XXXXXX")
        ACTIVE_TMPD="$tmpd"
        
        tmpf="$tmpd/test.${BASESHELL}"
        tmpa="$tmpd/a.out.${BASESHELL}$opt"
        tmpl="$tmpd/a.log"
        out=""
        firstarg='first quote" and space'
        secondarg="secondWithSingleQuote'"

        args_echo=' fp:(1) sp:(2)'
        args_expected=" fp:${firstarg} sp:${secondarg}"
        sn_echo=' sn:(0)'
        sn_expected=" sn:${tmpa}"

        if [[ "${opt}" == "-H" ]] ; then
            args_echo=""
            args_expected=""
            sn_echo=""
            sn_expected=""
        elif [[ "${opt}" == "-p" ]] ; then
            sn_echo=""
            sn_expected=""
        fi

        default_echo="${shell}: Hello World${sn_echo}${args_echo}"
        expected="${shell}: Hello World${sn_expected}${args_expected}"

        arg_only_echo="${shell}: Hello World${args_echo}"
        arg_only_expected="${shell}: Hello World${args_expected}"

        {
            echo "#!$shell"
            if [[ "${shell#*/pyth}" != "$shell" ]] ; then
                default_echo="${default_echo//\(/\{}"
                default_echo="${default_echo//)/\}}"
                echo 'import sys; sys.stdout.write("'"${default_echo}"'".format(*sys.argv)+"\n")'
            elif [[ "$BASESHELL" == "rc" ]] ; then
                default_echo="${default_echo//\(/\$}"
                default_echo="${default_echo//)/}"
                arg_only_echo="${arg_only_echo//\(/\$}"
                arg_only_echo="${arg_only_echo//)/}"
                if [[ "$opt" != "-P" ]] ; then
                    echo "echo ${default_echo}"
                else
                    echo "echo ${arg_only_echo}"
                    expected="${arg_only_expected}"
                fi
            elif [[ "${shell#*/perl}" != "$shell" ]] ; then
                default_echo="${default_echo//\(/\$ARGV\[}"
                default_echo="${default_echo//)/\]}"
                default_echo="${default_echo//\$ARGV\[0\]/\$0}"
                default_echo="${default_echo//1/0}"
                default_echo="${default_echo//2/1}"
                echo 'print "'"${default_echo}"'";'
            elif [[ "${shell#*/csh}" != "$shell" ]] ; then
                arg_only_echo="${arg_only_echo//\(/\$}"
                arg_only_echo="${arg_only_echo//)/}"
                echo 'echo "'"${arg_only_echo}"'"'
                expected="${arg_only_expected}"
            else
                default_echo="${default_echo//\(/\$}"
                default_echo="${default_echo//)/}"
                echo 'echo "'"${default_echo}"'"'
            fi
        } > "$tmpf"
        
        # shellcheck disable=SC2086
        if ! "$shc" $opt -f "$tmpf" -o "$tmpa"; then
            out="COMPILATION_FAILED"
        elif [[ "$opt" == "-D" ]] ; then
            out=$("$tmpa" "$firstarg" "$secondarg" 2>/dev/null || true)
        else
            out=$("$tmpa" "$firstarg" "$secondarg" 2>&1 || true)
        fi
        
        if [[ "$out" == "$expected" ]]; then
            echo    "===================================================="
            printf "=== %-20s [with shc %-2s]: %bPASSED%b\n" "$shell" "$opt" "${txtgrn}" "${txtrst}"
            echo    "===================================================="
            pc=$((pc + 1))
            rm -rf "$tmpd"
            ACTIVE_TMPD=""
        else
            echo    "===================================================="
            printf "=== %-20s [with shc %-2s]: %bFAILED%b\n" "$shell" "$opt" "${txtred}" "${txtrst}"
            echo    "===================================================="
            echo "  Files kept in '$tmpd'"
            printf "*** Expected Output:\n%s\n" "$expected"
            printf "*** Output:\n%s\n*** End of output\n" "$out"
            echo "$out" > "$tmpl"
            stat=1
            fc=$((fc + 1))
            ACTIVE_TMPD=""
        fi
    done
done

echo
echo "Test Summary"
echo "------------"

if (( pc > 0 )); then
    pt="${txtgrn}PASSED${txtrst}"
else
    pt="PASSED"
fi

if (( fc > 0 )); then
    ft="${txtred}FAILED${txtrst}"
else
    ft="FAILED"
fi

printf "%b: %d\n" "$pt" "$pc"
printf "%b: %d\n" "$ft" "$fc"
echo "------------"
echo

if (( stat > 0 )); then
    echo "EXIT with code $stat"
fi

exit "$stat"
