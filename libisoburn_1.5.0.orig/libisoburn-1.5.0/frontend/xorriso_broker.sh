#!/bin/sh

# Copyright (C) 2015
# Thomas Schmitt <scdbackup@gmx.net>, libburnia-project.org
# Provided under BSD license: Use, modify, and distribute as you like.

# set -x

# ---------------------------- functions ---------------------------

usage() {
  echo >&2
  echo "usage: $0 "'\' >&2
  echo "       [-xorriso path] id_string [-dev] iso_adr [xorriso_arguments ...]" >&2
  echo >&2
  echo "       This script looks for named pipe" >&2
  echo '         /tmp/xorriso_stdin_pipe_${id_string}' >&2
  echo "       which is supposed to be connected to a xorriso process." >&2
  echo "       If not found, the stdin pipe and a stdout pipe get created" >&2
  echo "       and a xorriso dialog process gets started and connected." >&2
  echo "       Each character in id_string must match [-+:.,=@0-9A-Za-z]." >&2
  echo "       If iso_adr differs from the previous run with the same id_string," >&2
  echo "       then any changes on the previous ISO are committed as session" >&2
  echo "       before command -dev is performed to load the meta data of" >&2
  echo "       the newly addressed ISO." >&2
  echo "       After this is done, the optionally given xorriso_arguments" >&2
  echo "       are written into the stdin pipe from where xorriso will read" >&2
  echo "       them as commands and their parameters." >&2
  echo >&2
}


# Make filenames safe for transport by wrapping them in quotes and
# escaping quotes in their text
xorriso_esc() {
  echo -n "'"
  echo -n "$1" | sed -e "s/'/'"'"'"'"'"'"'/g"
  echo -n "'"
}


# Send one or more command lines to xorriso
xorriso_send_cmd() {
  # $1 : the lines to send

  # >>> is it possible to have a timeout on echo ?

  if test -p "$cmd_pipe"
  then
    echo " $1" >"$cmd_pipe"
  else
    xorriso_is_running=0
    return 1
  fi
}


# Send command and wait for answer
xorriso_cmd_and_result() {
  # $1: command line for xorriso
  # $2: if not empty, grep expression for stdout
  if test "$xorriso_is_running" = 0
  then
    return 1
  fi
  xorriso_send_cmd "$1" || return 1
  if test -n "$2" 
  then
    cat "$result_pipe"
  else
    grep "$2" <"$result_pipe"
  fi
  return 0
}


# ------------------------------- main -----------------------------

# Argument interpreter

if test "$#" -lt 2
then
  usage "$0"
  exit 1
fi

xorriso=xorriso
if test o"$1" = o"-xorriso"
then
  xorriso="$2"
  shift 2
fi
export xorriso_is_running=0

if test "$#" -lt 2
then
  usage "$0"
  exit 1
fi

id_string=$(echo "$1" | sed -e 's/[^-+:.,=@0-9A-Za-z]/_/g' )
shift 1

# Ignore second argument -dev
if test o"$1" = o"-dev"
then
  shift 1
  if test "$#" -lt 1
  then
    usage "$0"
    exit 1
  fi
fi
device="$1"
shift 1

# Perform the action

export cmd_pipe=/tmp/xorriso_stdin_pipe_$id_string
export result_pipe=/tmp/xorriso_stdout_pipe_$id_string

if test -p "$cmd_pipe"
then
  xorriso_is_running=1
else
  xorriso_is_running=0
fi
if test "$xorriso_is_running" = "0"
then
  # xorriso is not started yet

  # Check for xorriso version which knows command -named_pipe_loop
  echo "Checking xorriso version ..." >&2
  xorriso_version_req="1.3.2"
  version=$("$xorriso" -version | grep '^xorriso version' |
            sed -e 's/^xorriso version   :  //')
  smallest=$( (echo "$xorriso_version_req" ; echo "$version" ) | \
             sort | head -1)
  if test "$smallest" = "$xorriso_version_req"
  then
    dummy=dummy
  else
    echo "$0 : FATAL : Need xorriso version >= $xorriso_version_req" >&2
    echo "Found version: $version" >&2
    exit 2
  fi

  if mknod "$cmd_pipe" p
  then
    echo "Created named pipe for xorriso commands: $cmd_pipe" >&2
  else
    echo "Failed to create named pipe for xorriso commands: $cmd_pipe" >&2
    exit 3
  fi
  if mknod "$result_pipe" p
  then
    echo "Created named pipe for xorriso result channel: $result_pipe" >&2
  else
    echo \
     "Failed to create named pipe for xorriso result channel: $result_pipe" >&2
    if rm "$cmd_pipe"
    then
      echo "Removed named pipe for xorriso commands: $cmd_pipe" >&2
    fi
    exit 3
  fi
  echo "Starting xorriso process ..." >&2
  "$xorriso" -abort_on NEVER -for_backup \
             -named_pipe_loop cleanup:buffered "$cmd_pipe" "$result_pipe" "-" \
             >&2 &
  # (stdout is redirected to stderr, in order not to keep a pipe waiting for
  #  input from the still open stdout copy of the background process.
  #  -named_pipe_loop will disconnect xorriso result channel from stdout.)
  xorriso_is_running=1
fi

# Inquire current xorriso -dev
xorriso_device=$(xorriso_cmd_and_result "-status -dev" "^-dev" | \
                 sed -e 's/^-dev //')
if echo " $device" | grep "^ '" >/dev/null
then
  quoted="$device"
else
  quoted=$(xorriso_esc "$device")
fi
if test "$xorriso_device" = "$quoted"
then
  dummy=dummy
else
  # Inquire the need for a -commit command
  pending=$(xorriso_cmd_and_result "-changes_pending show_status" \
                                   "^-changes_pending" \
            | sed -e 's/^-changes_pending //')
  if test "$pending" = "yes"
  then
    if xorriso_cmd_and_result "-commit"
    then
      dummy=dummy
    else
      exit 1
    fi
  fi
  # Now change ISO filesystem
  if xorriso_cmd_and_result "-dev $device"
  then
    xorriso_device="$device"
  else
    exit 1
  fi
fi

test "$*" = "" && exit 0

if xorriso_cmd_and_result "$*"
then
  dummy=dummy
else
  exit 1
fi

exit 0

