#!/usr/bin/ksh -x
# Audit & Hardening by HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION (2026)
echo "\$@ is $*"
echo "command line: $0 $*"
echo "hello world"
# Added
echo "[$$] PAUSED... Hit return!"
# shellcheck disable=SC2034
read -r DUMMY
exit 0
