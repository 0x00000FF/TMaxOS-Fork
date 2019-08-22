#!/bin/bash
#
# Demo of a shell frontend that communicates with a xorriso slave via
# two named pipes.
#
# This script creates two named pipes and starts xorriso with command
#  -named_pipes_loop cleanup /tmp/xorriso_stdin_pipe_$$ xorriso_stdin_pipe_$$ -
# Its main loop prompts the user for commands, sends them to xorriso,
# receives the replies, and parses them by xorriso command
# -msg_op parse_silently. The resulting words are printed to stdout.
#
# xorriso removes the two pipes when it finishes execution of -named_pipes_loop
# regularly. (E.g. because of commands -end or -rollback_end or because of
# name loop control message "end_named_pipe_loop".)
# The vanishing of the pipe files tells this script that xorriso is gone.
#
#
# Copyright (C) 2013
# Thomas Schmitt <scdbackup@gmx.net>, libburnia-project.org
# Provided under BSD license: Use, modify, and distribute as you like.
#

# What xorriso program to use
xorriso=xorriso
if test o"$1" = o"-xorriso"
then
  xorriso="$2"
fi

# Version of xorriso and minimum requirement by this script
export xorriso_version=
export xorriso_version_req=1.3.1

# Info about the xorriso slave process
export xorriso_is_running=0
export xorriso_pid=0
export xorriso_will_end=0

# Will be set to 1 before this script ends normally
export normal_end=0


# ---------------- An interpreter for quoted xorriso replies ----------------

# xorriso commands like -lsl wrap filenames into quotation marks in order
# to unambigously represent any character byte except the 0-byte.
# This piece of code parses input strings into words by letting xorriso
# command -msg_op "parse_silently" do the hard work.
# The input strings should be composed by concatenating input lines with
# newline characters between them. Begin by submitting a single line (without
# newline at its end) and retry with an appended further line, if
#   xorriso_parse
# returns 1. See below xorriso_cmd_and_handle_result() for an example.


# The parsed reply words.
# Valid are reply_array[0] to reply_array[reply_count-1)]
export reply_array
export reply_count


# Interpret reply of -msg_op parse
xorriso_recv_parse_reply() {
  reply_count=0
  unset reply_array
  export reply_array
  ret=-1
  read ret
  if test "$ret" -lt 0 -o -z "$ret"
  then
    echo "Unexpected text as first reply line of -msg_op parse" >&2
    xorriso_is_running=0
    return 2
  fi
  test "$ret" = 0 && return "1"  
  read num_strings
  string_count=0
  while true
  do
    test "$string_count" -ge "$num_strings" && break
    read num_lines
    line_count=0
    acc=
    while true
    do
      test "$line_count" -ge "$num_lines" && break
      read line
      test "$line_count" -gt 0 && acc="$acc"$'\n'
      acc="$acc""$line"
      line_count=$(($line_count + 1))
    done
    reply_array["$string_count"]="$acc"
    string_count=$(($string_count + 1))
  done
  reply_count="$num_strings"
  return 0
}


# Parse a quoted multi-line string into words
xorriso_parse() {
  # $1 : The string which shall be parsed
  # $2 : The number of concatenated input lines (= number of newlines + 1)
  # return: 0= array is valid , 1= line incomplete , 2= other error

  test "$xorriso_is_running" = 0 && return 1
  xorriso_send_cmd "msg_op parse_silently "'"'"'' '' 0 0 $2"'"'$'\n'"$1" || \
    return 2
  xorriso_recv_parse_reply <"$result_pipe" || xorriso_is_running=0
  ret=$?
  test "$xorriso_is_running" = 0 && ret=2
  return "$ret"
}


# ------------- End of interpreter for quoted xorriso replies --------------


# Send one or more command lines to xorriso
xorriso_send_cmd() {
  # $1 : the lines to send

  # >>> is it possible to have a timeout on echo ?

  if test -p "$cmd_pipe"
  then
    echo -E "$1" >"$cmd_pipe"
  else
    xorriso_is_running=0
    return 1
  fi
}


# Make filenames safe for transport by wrapping them in quotes and
# escaping quotes in their text
xorriso_esc() {
  echo -n "'" 
  echo -n "$1" | sed -e "s/'/'"'"'"'"'"'"'/g"
  echo -n "'"
}


# A handler function for xorriso_cmd_and_handle_result
xorriso_reply_to_stdout() {
    echo "${reply_array[*]}"
}


# Let a handler inspect the result lines of a xorriso command line
xorriso_cmd_and_handle_result() {
  # $1: handler command word and possibly argument words
  # $2: command line for xorriso

  if test "$xorriso_is_running" = 0
  then
    return 1
  fi

  handler="$1"
  xorriso_send_cmd "$2" || return 1
  res=$(cat "$result_pipe")
  ret=$?
  if test "$xorriso_will_end" = 1 -o "$xorriso_is_running" = 0 -o "$ret" -ne 0
  then
    test -n "$res" && echo -n "$res"
    xorriso_is_running=0
    test "$ret" = 0 || return 1
    return 0
  fi
  test -z "$res" && return 0
  echo "$res" | \
  while read line
  do
    line_count=1
    while true
    do
      xorriso_parse "$line" "$line_count"
      ret=$?
      test "$ret" = 0 && break
      if test "$ret" = 2
      then
        return 1
      fi
      read addon
      line="$line"$'\n'"$addon"
      line_count=$(expr "$line_count" + 1)
    done
    # One can now make use of reply_array[0...(reply_count-1)]
    $handler
  done
  return 0
}


# Execute -version and let xorriso_version_handler interpret reply
xorriso_check_version() {
  lookfor='^xorriso version   :  '
  xorriso_version=$("$xorriso" -version 2>/dev/null | grep "$lookfor" | \
                    sed -e "s/${lookfor}//")
  ret=$?
  if test "$ret" -ne 0 -o "$xorriso_version" = ""
  then
    echo "SORRY: Program run '${xorriso}' -version did not yield a result." >&2
    echo >&2
    exit 2
  fi
  smallest=$((echo "$xorriso_version_req" ; echo "$xorriso_version" ) | \
             sort | head -1)
  test "$smallest" = "$xorriso_version_req" && return 0
  echo "SORRY: xorriso version too old: ${xorriso_version} . Need at least xorriso-${xorriso_version_req} ." >&2
  echo >&2
  exit 2
}


# To be executed on exit
xorriso_cleanup() {

  send_end_cmd=0
  if test -p "$cmd_pipe" -a "$xorriso_is_running" = 1
  then
    if test "$normal_end" = 0
    then
      echo "Checking whether xorriso is still running ..." >&2
      set -x
      # Give xorriso time to abort
      sleep 1
      if ps  | grep '^'"$xorriso_pid" >/dev/null
      then

        # >>> try to further confirm xorriso identity

        send_end_cmd=1
      fi
    else
      send_end_cmd=1
    fi
  fi
  test "$normal_end" = 0 && set -x
  if test "$send_end_cmd" = 1
  then
    echo "Sending xorriso an -end command ..." >&2
    xorriso_send_cmd "end" && \
    test -p "$result_pipe" && cat "$result_pipe" >/dev/null
  fi
  test -p "$cmd_pipe" && rm "$cmd_pipe"
  test -p "$result_pipe" && rm "$result_pipe"
}


# ---------------------------------- main ---------------------------------

# Choose pipe names
export cmd_pipe=/tmp/xorriso_stdin_pipe_$$
export result_pipe=/tmp/xorriso_stdout_pipe_$$

# Check the program whether it is modern enough
xorriso_check_version "$xorriso"

# Prepare for then end of this script
trap xorriso_cleanup EXIT

# Create the pipes and start xorriso
mknod "$cmd_pipe" p
mknod "$result_pipe" p
"$xorriso" -abort_on NEVER -for_backup \
           -named_pipe_loop cleanup:buffered "$cmd_pipe" "$result_pipe" "-" &
xorriso_pid=$!
xorriso_is_running=1

# Get a sign of life from xorriso before issuing the loop prompt
xorriso_cmd_and_handle_result xorriso_reply_to_stdout \
                    "print_info 'xorriso process ${xorriso_pid} started by $0'"
echo >&2


# Now get commands from the user, send them to xorriso and display them
# via the simple handler xorriso_reply_to_stdout()
while test "$xorriso_is_running" = 1
do
  if test -p "$cmd_pipe"
  then
    echo -n "xorriso> " >&2
  else
    echo "$0 : Lost contact to xorriso process $xorriso_pid" >&2
    xorriso_is_running=0
    break
  fi
  read line
  if echo "$line" | grep '^-*end$' >/dev/null
  then
    break
  fi
  if echo "$line" | grep '^-*rollback_end$' >/dev/null
  then
    xorriso_will_end=1
  fi
  xorriso_cmd_and_handle_result xorriso_reply_to_stdout "$line"
done

# Prevent set -x in the exit handler
normal_end=1

