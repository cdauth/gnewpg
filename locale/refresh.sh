cd "$(dirname "$0")"

cat << EOF | xargs -n1 -I{} echo '_("[{}]");' >> fixedStrings.tmp.js
SIG_16
SIG_17
SIG_18
SIG_19
SIG_24
SIG_25
SIG_31
SIG_32
SIG_40
SIG_48
EOF

( echo fixedStrings.tmp.js; ls -1 ../*.js; ls -1 ../pages/*.js; ls -1 ../pages/*.soy ) | xgettext -f- -dgnewpg -ognewpg.pot -LPython --from-code=UTF-8 --add-comments="I18N:" -k_ -kError_

rm -f fixedStrings.tmp.js
