#!/usr/bin/env sh
set -eu

bad=0
tmp_file_list=$(mktemp)
find . -type f -name '*.java' ! -path '*/target/*' ! -path './.git/*' > "$tmp_file_list"

while IFS= read -r f; do
  awk -v file="$f" '
    function skip(line) {
      return line ~ /^[[:space:]]*$/ ||
             line ~ /^[[:space:]]*\/\// ||
             line ~ /^[[:space:]]*\/\*/ ||
             line ~ /^[[:space:]]*\*/ ||
             line ~ /^[[:space:]]*\*\//
    }
    {
      if (skip($0)) next
      if ($0 ~ /^\t+/) {
        printf "%s:%d: leading tab indent\n", file, NR
        bad = 1
      } else if (match($0, /^ +/)) {
        n = RLENGTH
        if (n % 2 == 1) {
          printf "%s:%d: odd leading spaces (%d)\n", file, NR, n
          bad = 1
        }
      }
    }
    END { exit bad }
  ' "$f" || bad=1
done < "$tmp_file_list"

rm -f "$tmp_file_list"

exit $bad
