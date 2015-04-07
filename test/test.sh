#!/bin/bash
(set -o igncr) 2>/dev/null && set -o igncr; # comment is needed
#                                           # hack for cygwin bash
#                                           #  no-op for other
#
# Test various command line testable aspects of the Wireshark tools
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2005 Ulf Lamping
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# an existing capture file
USE_COLOR=1
RUN_SUITE=""
PRINT_USAGE=0

# Ensure cygwin bin dir is on the path if running under it
if [[ $OSTYPE == "cygwin" ]]; then
	PATH="$PATH:/usr/bin"
fi

while getopts "chs:" OPTION ; do
	case $OPTION in
		c) USE_COLOR=0 ;;
		h) PRINT_USAGE=1 ;;
		s) RUN_SUITE="$OPTARG" ;;
		*) echo "Unknown option: " $OPTION $OPTARG
	esac
done

shift $(( $OPTIND - 1 ))

if [ $PRINT_USAGE -ne 0 ] ; then
        THIS=`basename $0`
        cat <<FIN
Usage: $THIS [-c] [-h] [-s <suite>]
  -c: Disable color output
  -h: Print this message and exit
  -s: Run a suite.  Must be one of:
      all
      capture
      clopts
      decryption
      fileformats
      io
      nameres
      prerequisites
      unittests
      wslua
FIN
        exit 0
fi

MYDIR=$(dirname $0)
if [ -d run ]; then
	if [ -e run/tshark -o -e run/dumpcap -o -e run/rawshark ]; then
		WS_BIN_PATH=${WS_BIN_PATH:-$(cd run && pwd)}
		WS_QT_BIN_PATH=${WS_QT_BIN_PATH:-$WS_BIN_PATH}
	fi
fi
source $MYDIR/test-backend.sh
source $MYDIR/config.sh

# needed by some tests
TEST_OUTDIR=$(mktemp -d)
TEST_OUTDIR_CLEAN=${TEST_OUTDIR_CLEAN:-1}
if [ -z "$TEST_OUTDIR" ] || ! cd "$TEST_OUTDIR"; then
	# If for any reason the temporary tests output directory cannot be created...
	TEST_OUTDIR=.
	TEST_OUTDIR_CLEAN=0
fi

# Configuration paths
HOME_ENV="HOME"
HOME_PATH="$TEST_OUTDIR/home"
CONF_PATH="$HOME_PATH/.wireshark"

if [ "$WS_SYSTEM" == "Windows" ] ; then
	HOME_ENV="APPDATA"
	HOME_PATH="`cygpath -w $HOME_PATH`"
	CONF_PATH="$HOME_PATH/Wireshark"
	CAPTURE_DIR="`cygpath -w $CAPTURE_DIR`"
	TESTS_DIR="`cygpath -w $TESTS_DIR`"
fi

mkdir -p $CONF_PATH

source $TESTS_DIR/suite-clopts.sh
source $TESTS_DIR/suite-io.sh
source $TESTS_DIR/suite-capture.sh
source $TESTS_DIR/suite-unittests.sh
source $TESTS_DIR/suite-fileformats.sh
source $TESTS_DIR/suite-decryption.sh
source $TESTS_DIR/suite-nameres.sh
source $TESTS_DIR/suite-wslua.sh

test_cleanup() {
	if [ $TEST_OUTDIR_CLEAN = 1 ]; then
		# display contents of test outputs, ignore directory:
		# home (decryption suite)
		grep -r . --exclude-dir=home .
		rm -rf "$TEST_OUTDIR"
	elif ! rmdir "$TEST_OUTDIR" 2>/dev/null; then
		# if directory is non-empty, print directory
		echo "Test results are available in $TEST_OUTDIR"
	fi
}
trap test_cleanup EXIT

#check prerequisites
test_step_prerequisites() {

	NOTFOUND=0
	for i in "$WIRESHARK" "$WIRESHARK_GTK" "$TSHARK" "$CAPINFOS" "$DUMPCAP" ; do
		if [ ! -x $i ]; then
			echo "Couldn't find $i"
			NOTFOUND=1
		fi
	done
	if [ $NOTFOUND -eq 1 ]; then
		test_step_failed "Tool not found"
		exit 1
	else
		test_step_ok
	fi
}

# Dump version information
test_step_tshark_version() {
	test_remark_add "Printing TShark version"
	$TSHARK -v
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to print version information"
		return
	fi
	test_step_ok
}


prerequisites_suite() {
	test_step_add "Prerequisites settings" test_step_prerequisites
	test_step_add "Version information" test_step_tshark_version
}

test_suite() {
	test_suite_add "Prerequisites" prerequisites_suite
	test_suite_add "Command line options" clopt_suite
	test_suite_add "File I/O" io_suite
	test_suite_add "Capture" capture_suite
	test_suite_add "Unit tests" unittests_suite
	test_suite_add "File formats" fileformats_suite
	test_suite_add "Decryption" decryption_suite
	test_suite_add "Name Resolution" name_resolution_suite
	test_suite_add "Lua API" wslua_suite
}


#test_set_output OFF # doesn't work
#test_set_output DOTTED
test_set_output VERBOSE


#test_suite_run "TShark command line options" clopt_suite
#test_suite_run "TShark capture" capture_suite


# all
#test_suite_run "All" test_suite
#test_suite_show "All" test_suite

if [ -n "$RUN_SUITE" ] ; then
	case $RUN_SUITE in
		"all")
			test_suite_run "All" test_suite
			exit $? ;;
		"capture")
			test_suite_run "Capture" capture_suite
			exit $? ;;
		"clopts")
			test_suite_run "Command line options" clopt_suite
			exit $? ;;
		"decryption")
			test_suite_run "Decryption" decryption_suite
			exit $? ;;
		"fileformats")
			test_suite_run "File formats" fileformats_suite
			exit $? ;;
		"io")
			test_suite_run "File I/O" io_suite
			exit $? ;;
		"nameres")
			test_suite_run "Name Resolution" name_resolution_suite
			exit $? ;;
		"prerequisites")
			test_suite_run "Prerequisites" prerequisites_suite
			exit $? ;;
		"unittests")
			test_suite_run "Unit tests" unittests_suite
			exit $? ;;
		"wslua")
			test_suite_run "Lua API" wslua_suite
			exit $? ;;
	esac
fi

MENU_LEVEL=0

menu_title[0]="All"
menu_function[0]=test_suite

echo "----------------------------------------------------------------------"

for ((a=0; a <= 100000000000 ; a++))
do
	TEST_STEPS[0]=0			# number of steps of a specific nesting level

	#echo $current_title $current_function
	test_suite_show "${menu_title[MENU_LEVEL]}" "${menu_function[MENU_LEVEL]}"
	echo "1-$TEST_STEPS  : Select item"
	echo "Enter: Test All"
	if [[ ! $MENU_LEVEL -eq 0 ]]; then
		echo "U    : Up"
	fi
	echo "Q    : Quit"
	echo ""
	read -n1 key
	newl=$'\x0d'
	echo "$newl----------------------------------------------------------------------"

	TEST_STEPS[0]=0			# number of steps of a specific nesting level

	#echo $key
	case "$key" in
		"Q" | "q")
		exit 0
	;;
		"T" | "t" | "")
LIMIT_RUNS=1
for ((a_runs=1; a_runs <= LIMIT_RUNS ; a_runs++))  # Double parentheses, and "LIMIT" with no "$".
do
		test_suite_run "${menu_title[MENU_LEVEL]}" "${menu_function[MENU_LEVEL]}"
done
		echo "----------------------------------------------------------------------"
	;;
		"U" | "u")
		if [[ ! $MENU_LEVEL -eq 0 ]]; then
			let "MENU_LEVEL -= 1"
			#echo "----------------------------------------------------------------------"
		fi
	;;
		"1")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[1]}
		menu_function[MENU_LEVEL]=${test_function[1]}
	;;
		"2")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[2]}
		menu_function[MENU_LEVEL]=${test_function[2]}
	;;
		"3")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[3]}
		menu_function[MENU_LEVEL]=${test_function[3]}
	;;
		"4")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[4]}
		menu_function[MENU_LEVEL]=${test_function[4]}
	;;
		"5")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[5]}
		menu_function[MENU_LEVEL]=${test_function[5]}
	;;
		"6")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[6]}
		menu_function[MENU_LEVEL]=${test_function[6]}
	;;
		"7")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[7]}
		menu_function[MENU_LEVEL]=${test_function[7]}
	;;
		"8")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[8]}
		menu_function[MENU_LEVEL]=${test_function[8]}
	;;
		"9")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[9]}
		menu_function[MENU_LEVEL]=${test_function[9]}
	;;

	esac
done

# Editor modelines
#
# Local Variables:
# sh-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# ex: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
