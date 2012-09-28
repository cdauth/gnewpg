cd "$(dirname "$0")"

FAQNUMBER=3

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
PKALGO_1
PKALGO_2
PKALGO_3
PKALGO_16
PKALGO_17
HASHALGO_1
HASHALGO_2
HASHALGO_3
HASHALGO_8
HASHALGO_9
HASHALGO_10
HASHALGO_11
SECURITY_-1
SECURITY_0
SECURITY_1
SECURITY_2
SECURITY_3
REVOK_0
REVOK_1
REVOK_2
REVOK_3
REVOK_32
EOF

for((i=1; $i<=$FAQNUMBER; i++)); do
	echo '_("[FAQ_'$i']");' >> fixedStrings.tmp.js
	echo '_("[FAQ_'$i'_TITLE]");' >> fixedStrings.tmp.js
done

( echo fixedStrings.tmp.js; ls -1 ../*.js; ls -1 ../pages/*.js; ls -1 ../pages/*.soy ) | xgettext -f- -dgnewpg -ognewpg.pot -LPython --from-code=UTF-8 --add-comments="I18N:" -k_ -kError_

rm -f fixedStrings.tmp.js
