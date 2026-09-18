#!/usr/bin/env sh
# Definition-of-done checks for the layering rules. Each check must find
# nothing. The lint job (forbidigo) mirrors the rules a linter can express.
set -eu
cd "$(dirname "$0")/.."
fail=0

# files <exclude-regex>: non-test Go sources under internal/ and cmd/ whose
# path does not match the regex. Always ends with /dev/null so grep never
# waits on stdin when the list is empty.
files() {
  find internal cmd -name '*.go' ! -name '*_test.go' | grep -vE "$1" || true
  echo /dev/null
}

check() {
  name=$1; shift
  if out=$("$@" 2>/dev/null) && [ -n "$out" ]; then
    echo "FAIL: $name"; echo "$out" | sed 's/^/  /'; fail=1
  fi
}

check "ops is silent" sh -c 'grep -nE "fmt\.(Print|Fprint)|os\.Std(in|out|err)|charmbracelet" $(find internal/ops -name "*.go" ! -name "*_test.go") /dev/null'
check "printing only in ui" sh -c "grep -n 'fmt\.Print' \$(find internal cmd -name '*.go' ! -name '*_test.go' | grep -v '^internal/ui/' || true) /dev/null"
check "huh only in ui" sh -c "grep -l 'charmbracelet/' \$(find internal cmd -name '*.go' | grep -v '^internal/ui/' || true) /dev/null"
check "writes only in repo" sh -c "grep -nE 'os\.(WriteFile|Create|Rename|Remove|MkdirAll)\(' \$(find internal cmd -name '*.go' ! -name '*_test.go' | grep -vE '^internal/(repo|testutil)/' || true) /dev/null"
check "subprocesses only in ports" sh -c "grep -n 'exec\.Command' \$(find internal cmd -name '*.go' ! -name '*_test.go' | grep -vE '^internal/(proc|kube|gcp|seal)/' || true) /dev/null"
check "os.Exit only in main" sh -c "grep -n 'os\.Exit' \$(find internal -name '*.go' ! -name '*_test.go') /dev/null"
check "no init() or mutable package vars in cli" sh -c "grep -nE '^func init\(|^var [a-z]' \$(find internal/cli -name '*.go' ! -name '*_test.go') /dev/null"
check "no source file over 400 lines" sh -c "wc -l \$(find internal cmd -name '*.go' ! -name '*_test.go') | awk '\$1>400 && \$2!=\"total\"'"
check "old world gone" sh -c "ls -d internal/files internal/state internal/reseal internal/cli2 internal/template cmd/waxseal-next 2>/dev/null"
check "no committed binaries" sh -c "git ls-files | grep -E '\.exe$|^dev/'"

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "definition of done: all checks pass"
