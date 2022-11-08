#!/bin/sh
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#
# file:        rohc_stats.sh
# description: Generate some cool graphs about ROHC library compression
# author:      Didier Barvaux <didier@barvaux.org>
#

# parse parameters
capture="$1"
output_dir="$2"
verbose="$3"
if [ -z "${capture}" ] || [ ! -f "${capture}" ] ; then
	echo "usage: $0 stream.pcap [output-directory [verbose]]" >&2
	exit 1
fi
capture_name="`basename "${capture}" .pcap`"
if [ -z "${output_dir}" ] ; then
	output_dir="${PWD}/rohc_stats_output/"
fi

# check that all tools are available
test -z "${GEN}" && GEN="`dirname "$0"`/`basename "$0" .sh`"
test ! -f "${GEN}" && GEN="`which rohc_stats`"
test -z "${GNUPLOT}" && GNUPLOT="`which gnuplot`"
test -z "${SED}" && SED="`which sed`"
test -z "${GREP}" && GREP="`which grep`"
test -z "${AWK}" && AWK="`which gawk`"
test -z "${AWK}" && AWK="`which awk`"
if [ -z "${GEN}" ] ; then
	echo "the rohc_stats tool was not found, please install it." >&2
	exit 1
fi
if [ -z "${GNUPLOT}" ] ; then
	echo "the gnuplot tool was not found, please install it." >&2
	exit 1
fi
if [ -z "${AWK}" ] ; then
	echo "no awk-like tool available, please install one of the gawk, mawk, "\
	     "nawk, or awk tool." >&2
	exit 1
fi
if [ -z "${GREP}" ] ; then
	echo "no grep-like tool available, please install one of the grep, or "\
	     "ggrep, tool." >&2
	exit 1
fi
if [ -z "${SED}" ] ; then
	echo "sed tool not available, please install it." >&2
	exit 1
fi

# run the statistics application and retrieve its output
OUTPUT=$( ${GEN} smallcid ${capture} 2>/dev/null )
if [ $? -ne 0 ] ; then
	echo "compression failed for capture '${capture}'" >&2
	exit 1
fi


echo "generate statistics for '${capture}':"

# create the output directory
mkdir -p "${output_dir}" || exit 1

# create the raw output
RAW_OUTPUT="${output_dir}/raw.txt"
[ "${verbose}" = "verbose" ] && echo -ne "\trun statistics application... "
echo -e "${OUTPUT}" | ${GREP} "^STAT" > ${RAW_OUTPUT} || exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# create the graph with context modes
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate graph with context modes... "
echo -e "set terminal png\n" \
        "set output '${output_dir}/modes.png'\n" \
        "set title 'Compression modes for ${capture_name}'\n" \
        "set xlabel 'packet number in capture'\n" \
        "plot [] [0:4] '${RAW_OUTPUT}' using 2:3:yticlabels(4) title columnhead(3)" \
	| ${GNUPLOT} 2>/dev/null \
	|| exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# create the graph with context states
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate graph with context states... "
echo -e "set terminal png\n" \
        "set output '${output_dir}/states.png'\n" \
        "set title 'Compression states for ${capture_name}'\n" \
        "set xlabel 'packet number in capture'\n" \
        "plot [] [0:4] '${RAW_OUTPUT}' using 2:5:yticlabels(6) title columnhead(5)" \
	| ${GNUPLOT} 2>/dev/null \
	|| exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# create the graph with packet types
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate graph with packet types... "
echo -e "set terminal png\n" \
        "set output '${output_dir}/packet_types.png'\n" \
        "set title 'ROHC packet types for ${capture_name}'\n" \
        "set xlabel 'packet number in capture'\n" \
        "plot [] [-1:14] '${RAW_OUTPUT}' using 2:7:yticlabels(8) title columnhead(7)" \
	| ${GNUPLOT} 2>/dev/null \
	|| exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# create the graph with (un)compressed packet sizes
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate graph with (un)compressed packet sizes... "
echo -e "set terminal png\n" \
        "set output '${output_dir}/packet_sizes.png'\n" \
        "set title 'Packet sizes for compression of ${capture_name}'\n" \
        "set xlabel 'packet number in capture'\n" \
        "set ylabel 'packet size (bytes)'\n" \
        "plot '${RAW_OUTPUT}' using 2:9 title columnhead(9) with lines," \
        "     '${RAW_OUTPUT}' using 2:11 title columnhead(11) with lines" \
	| ${GNUPLOT} 2>/dev/null \
	|| exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# create the graph with (un)compressed header sizes
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate graph with (un)compressed header sizes... "
echo -e "set terminal png\n" \
        "set output '${output_dir}/header_sizes.png'\n" \
        "set title 'Header sizes for compression of ${capture_name}'\n" \
        "set xlabel 'packet number in capture'\n" \
        "set ylabel 'header size (bytes)'\n" \
        "plot '${RAW_OUTPUT}' using 2:10 title columnhead(10) with lines," \
        "     '${RAW_OUTPUT}' using 2:12 title columnhead(12) with lines" \
	| ${GNUPLOT} 2>/dev/null \
	|| exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# create context mode counters
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate context mode counters... "
for CONTEXT_MODE in "U-mode" "O-mode" "R-mode" ; do
	${AWK} "\$4 == \"${CONTEXT_MODE}\" { print \$11 }" \
	       "${RAW_OUTPUT}" \
		| wc -l > ${output_dir}/context_mode_${CONTEXT_MODE}.count \
		|| exit 1
done
[ "${verbose}" = "verbose" ] && echo "done"

# create context state counters
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate context state counters... "
for CONTEXT_STATE in "IR" "FO" "SO" ; do
	${AWK} "\$6 == \"${CONTEXT_STATE}\" { print \$11 }" \
	       "${RAW_OUTPUT}" \
		| wc -l > ${output_dir}/context_state_${CONTEXT_STATE}.count \
		|| exit 1
done
[ "${verbose}" = "verbose" ] && echo "done"

# create packet type counters
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate packet type counters... "
for PACKET_TYPE in "IR" "IR-DYN" \
                   "UO-0" \
                   "UO-1" "UO-1-ID" "UO-1-TS" "UO-1-RTP" \
                   "UOR-2" "UOR-2-RTP" "UOR-2-ID" "UOR-2-TS" \
                   "CCE" "CCE(off)" \
                   "Normal"
do
	${AWK} "\$8 == \"${PACKET_TYPE}\" { print \$11 }" \
	       "${RAW_OUTPUT}" \
		| wc -l > ${output_dir}/packet_type_${PACKET_TYPE}.count \
		|| exit 1
done
[ "${verbose}" = "verbose" ] && echo "done"

# create packet compression gain
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate packet compression gain... "
${AWK} 'BEGIN { uncomp=0 ; comp=0 }\
        $2 != "\"packet" { uncomp+=$9 ; comp+=$11 }\
        END { printf "scale=2\n100-" comp "*100/" uncomp "\n" }' \
     "${RAW_OUTPUT}" \
	| bc > ${output_dir}/packet_compression.gain \
	|| exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# create header compression gain
[ "${verbose}" = "verbose" ] && echo -ne "\tcreate header compression gain... "
${AWK} 'BEGIN { uncomp=0 ; comp=0 }\
        $2 != "\"packet" { uncomp+=$10 ; comp+=$12 }\
        END { printf "scale=2\n100-" comp "*100/" uncomp "\n" }' \
     "${RAW_OUTPUT}" \
	| bc > ${output_dir}/header_compression.gain \
	|| exit 1
[ "${verbose}" = "verbose" ] && echo "done"

# generate the HTML page which summarize all the results
HTML_OUTPUT="${output_dir}/index.html"
echo -n "" > ${HTML_OUTPUT}
echo -e "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">" >> ${HTML_OUTPUT}
echo -e "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">" >> ${HTML_OUTPUT}
echo -e "\t<head>" >> ${HTML_OUTPUT}
echo -e "\t\t<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\" />" >> ${HTML_OUTPUT}
echo -e "\t\t<title>ROHC compression statistics</title>" >> ${HTML_OUTPUT}
echo -e "\t\t<style type=\"text/css\">" >> ${HTML_OUTPUT}
echo -e "\t\t\tbody { font-size: small; }" >> ${HTML_OUTPUT}
echo -e "\t\t\ttable, tr, th, td { border: solid thin black; border-collapse: collapse; width: 33%; }" >> ${HTML_OUTPUT}
echo -e "\t\t\tth { vertical-align: top; }" >> ${HTML_OUTPUT}
echo -e "\t\t\ttable { width: 95%; margin: 2%; }" >> ${HTML_OUTPUT}
echo -e "\t\t</style>" >> ${HTML_OUTPUT}
echo -e "\t</head>" >> ${HTML_OUTPUT}
echo -e "\t<body>" >> ${HTML_OUTPUT}

echo -e "\t\t<h1>ROHC compression statistics for '${capture_name}'</h1>" >> ${HTML_OUTPUT}

echo -e "\t\t<table>" >> ${HTML_OUTPUT}

echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"4\">Context modes</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Unidirectional Mode\">U-Mode</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./modes.png\">$(cat ${output_dir}/context_mode_U-mode.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td rowspan=\"4\"><img src=\"./modes.png\" /></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Bidirectional Optimistic Mode\">O-mode</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./modes.png\">$(cat ${output_dir}/context_mode_O-mode.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Bidirectional Reliable Mode\">R-mode</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./modes.png\">$(cat ${output_dir}/context_mode_R-mode.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\">&nbsp;</th>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"4\">Context states</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Initialisation &amp; Refresh\">IR</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./states.png\">$(cat ${output_dir}/context_state_IR.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td rowspan=\"4\"><img src=\"./states.png\" /></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"First Order\">FO</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./states.png\">$(cat ${output_dir}/context_state_FO.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Second Order\">SO</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./states.png\">$(cat ${output_dir}/context_state_SO.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\">&nbsp;</th>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"15\">Packet types</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Initialisation &amp; Refresh\">IR</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_IR.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"15\"><img src=\"./packet_types.png\" /></th>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Initialisation &amp; Refresh DYNamic\">IR-DYN</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_IR-DYN.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Unidirectional/Optimistic packet type 0\">UO-0</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UO-0.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"4\"><acronym title=\"Unidirectional/Optimistic packet type 1\">UO-1</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 for non-RTP profiles\">-</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UO-1.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 for RTP profile\">RTP</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UO-1-RTP.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 with IP-ID bits\">ID</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UO-1-ID.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 with RTP TS bits\">TS</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UO-1-TS.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"4\"><acronym title=\"Unidirectional/Optimistic/Reliable packet type 2\">UOR-2</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 for non-RTP profiles\">-</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UOR-2.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 for RTP profile\">RTP</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UOR-2-RTP.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 with IP-ID bits\">ID</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UOR-2-ID.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 with TS bits\">TS</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_UOR-2-TS.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"CCE packet type for UDP-Lite profile\">CCE</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_CCE.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"CCE(off) packet type for UDP-Lite profile\">CCE(off)</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_CCE\(off\).count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\"><acronym title=\"Normal packet type for Uncompressed profile\">Normal</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_types.png\">$(cat ${output_dir}/packet_type_Normal.count)</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\">&nbsp;</th>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"3\">Compression gain</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\">Packet</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./packet_sizes.png\">$(cat ${output_dir}/packet_compression.gain)&nbsp;%</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"3\"><img src=\"./packet_sizes.png\" /><img src=\"./header_sizes.png\" /></th>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\">Header</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<td><a href=\"./header_sizes.png\">$(cat ${output_dir}/header_compression.gain)&nbsp;%</a></td>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\">&nbsp;</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th>&nbsp;</th>" >> ${HTML_OUTPUT}
echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}
echo -e "\t\t</table>" >> ${HTML_OUTPUT}
echo -e "\t</body>" >> ${HTML_OUTPUT}
echo -e "</html>" >> ${HTML_OUTPUT}

[ "${verbose}" = "verbose" ] && echo ""
echo "HTML summary was created for you in \"${HTML_OUTPUT}\"."
[ "${verbose}" = "verbose" ] && echo ""

exit 0

