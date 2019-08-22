#!/bin/sh

# Copyright (C) 2015 - 2016
# Thomas Schmitt <scdbackup@gmx.net>, libburnia-project.org
# Provided under BSD license: Use, modify, and distribute as you like.

echo >&2
echo "frontend/grub-mkrescue-sed.sh manipulating xorriso arguments" >&2
echo >&2

# This script may be handed by its absolute path to grub-mkrescue
# via option --xorriso= . E.g.
#
#   mkdir minimal
#   touch minimal/empty-file.txt
#   grub-mkrescue -o output.iso minimal \
#         --xorriso=/home/thomas/xorriso-1.4.3./frontend/grub-mkrescue-sed.sh
#
# It will manipulate the xorriso arguments before they get executed by a
# xorriso program. Default is the neighboring ../../xorriso/xorriso program or,
# if that neighbor cannot be found, the system-wide installed xorriso.
#
# The mode "mjg" implements a layout which resembles Fedora LiveCD and Debian
# ISOs which are bootable by ISOLINUX for BIOS and GRUB2 for EFI.
# Its GPT is considered to be surplus, according to UEFI specs.
#
# The mode "mbr_only" implements an alternative layout according to UEFI 2.4,
# section 2.5.1 and table 16. No GTP, HFS+, or APM.
# This mode produces a mountable ISO 9660 partition 1 only if variable
# MKRESCUE_SED_PROTECTIVE is empty or set to "no".
#
# The mode "mbr_hfs" is like "mbr_only" but with HFS+ mentioned in APM.
# It is still compliant to UEFI with no potentially deceiving GPT.
# If you add xorrisofs option -part_like_isohybrid then no gap fillig APM
# partition will emerge.
#
# Mode "gpt_appended" represents the same layout as "mbr_only" by GPT rather
# than by MBR partition table. It differs from "original" by the fact that
# option -partition_offset 16 is implied and that the first partition may
# be used to mount the ISO 9660 filesystem. MKRESCUE_SED_PROTECTIVE is ignored,
# because neat GPT is indicated by the existence of a Protective MBR.
#
# These modes avoid duplicate storing of the EFI system partition "efi.img"
# by xorrisofs option  -e "--interval:appended_partition_${partno}:all::"
# which is new to xorriso-1.4.4.
# If "_copy" is appended to the mode name, then the file /efi.img will
# appear in the ISO 9660 filesystem and traditional -e "/efi.img" is used.
#
# "mbr_only_copy" is supposed to work with unmodified xorriso >= 1.3.2

#
#                              Variation settings
#
# The environment variables MKRESCUE_SED_* override the following
# default settings:

# Manipulation mode:
#  "mjg"         =  ESP in MBR+GPT+APM, with HFS+
#  "mbr_only"    =  ESP in MBR, without HFS+
#  "mbr_hfs"     =  ESP in MBR, HFS+ in APM
#  "gpt_appended" = ESP in GPT, without HFS+
#  $mode"_copy"  =  one of above modes, ESP in ISO and as appended partition
#  "original"    =  pass arguments unchanged
mode="mbr_only"
if test -n "$MKRESCUE_SED_MODE"
then
  mode="$MKRESCUE_SED_MODE"
fi

# First argument of -append_partition with mode "mjg". Values: 1 or 2.
partno=1
if test -n "$MKRESCUE_SED_PARTNO"
then
  partno="$MKRESCUE_SED_PARTNO"
fi

# Replacement for option --protective-msdos-label. Either itself or empty text.
# If the environment variable contains the word "no", this means empty.
protective=""
if test -n "$MKRESCUE_SED_PROTECTIVE"
then
  if test x"$MKRESCUE_SED_PROTECTIVE" = xno
  then
    protective=""
  elif test x"$MKRESCUE_SED_PROTECTIVE" = xyes
  then
    protective="--protective-msdos-label"
  else
    protective="$MKRESCUE_SED_PROTECTIVE"
  fi
fi

# "yes" shows xorriso arguments, "extra" additionally shows all input files.
debug=no
if test -n "$MKRESCUE_SED_DEBUG"
then
  debug="$MKRESCUE_SED_DEBUG"
fi

# The path to the program that will be executed with the converted arguments.
if test -n "$MKRESCUE_SED_XORRISO"
then
  xorriso="$MKRESCUE_SED_XORRISO"
else
  # Prefer neighboring xorriso binary over system-wide installed one.
  self_dir="$(dirname $(dirname "$0") )"
  if test -x "$self_dir"/xorriso/xorriso
  then
    xorriso="$self_dir"/xorriso/xorriso
  else
    xorriso="xorriso"
  fi
fi 

# MKRESCUE_SED_XORRISO_ARGS will be used as first arguments of the xorriso run.
# (Trailing xorriso arguments may be simply added to the grub-mkrescue
#  command line.)
# Each argument must be a single word. No whitespace. No quotation marks.


#
#                               Do the work 
#

# grub-mkrescue inquires features by running these arguments
if test "$*" = "-as mkisofs -help"
then
  "$xorriso" "$@"
  exit $?
fi  

echo "frontend/grub-mkrescue-sed.sh mode:  $mode" >&2
echo >&2

if test x"$debug" = xyes -o x"$debug" = xextra
then
  # Show arguments
  echo "##### Begin of received arguments" >&2
  echo "$0" >&2
  for i in "$@"
  do
    echo "$i" >&2
  done
  echo "##### End of received arguments" >&2
  echo >&2
fi

# Check for option -iso_mbr_part_type which is new in 1.4.8
iso_mbr_part_type=
if "$xorriso" -as mkisofs -help 2>&1 | grep iso_mbr_part_type >/dev/null
then
  iso_mbr_part_type="-iso_mbr_part_type 0x00"
fi

# Look for the name of the /tmp directory with the GRUB2 files.
# It is the next argument after -r. But as default accept any /tmp/grub.*
next_is_dir=0
dir="."
for i in "$@"
do
  if test x"$i" = x"-r"
  then
    next_is_dir=1
  elif test $next_is_dir = 1
  then
    next_is_dir=0
    if echo "$i" | grep '^/tmp/grub.' >/dev/null 2>&1
    then
      test -d "$i" && dir="$i"
    fi
  elif test "$dir" = "."
  then
    if echo "$i" | grep '^/tmp/grub.' >/dev/null 2>&1 
    then
      test -d "$i" && dir="$i"
    fi
  fi
done

if test x"$debug" = xextra
then
  # Show files on disk
  find "$dir"
fi

efi_tmp_name=
if test x"$mode" = xmjg
then
  # Exchange arguments for the experimental GRUB2 mjg layout
  efi_tmp_name=grub-mkrescue-sed-efi-img.$$
  mv "$dir"/efi.img /tmp/$efi_tmp_name
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/-no-pad -append_partition $partno 0xef \/tmp\/$efi_tmp_name/" \
    -e "s/--efi-boot efi\.img/-eltorito-alt-boot -e --interval:appended_partition_${partno}:all:: -no-emul-boot -isohybrid-gpt-basdat/" \
    -e "s/--protective-msdos-label/$protective -part_like_isohybrid/" \
     )

elif test x"$mode" = xmjg_copy
then
  # Exchange arguments for the experimental GRUB2 mjg layout
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/-no-pad -append_partition $partno 0xef \/tmp\/$(basename "$dir")\/efi.img/" \
    -e "s/--efi-boot efi\.img/-eltorito-alt-boot -e efi.img -no-emul-boot -isohybrid-gpt-basdat/" \
    -e "s/--protective-msdos-label/$protective -part_like_isohybrid/" \
     )

elif test x"$mode" = xmbr_only
then
  # Exchange arguments for no-HFS MBR-only layout
  efi_tmp_name=grub-mkrescue-sed-efi-img.$$
  mv "$dir"/efi.img /tmp/$efi_tmp_name
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/$iso_mbr_part_type -no-pad -append_partition 2 0xef \/tmp\/$efi_tmp_name/" \
    -e "s/--efi-boot efi\.img/-eltorito-alt-boot -e --interval:appended_partition_2:all:: -no-emul-boot/" \
    -e "s/-hfsplus .*CoreServices\/boot.efi//" \
    -e "s/--protective-msdos-label/$protective/" \
     )

elif test x"$mode" = xmbr_only_copy
then
  # Exchange arguments for no-HFS MBR-only layout
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/$iso_mbr_part_type -no-pad -append_partition 2 0xef \/tmp\/$(basename "$dir")\/efi.img/" \
    -e "s/-hfsplus .*CoreServices\/boot.efi//" \
    -e "s/--protective-msdos-label/$protective/" \
     )

elif test x"$mode" = xmbr_hfs
then
  # Exchange arguments for MBR and HFS+ layout
  efi_tmp_name=grub-mkrescue-sed-efi-img.$$
  mv "$dir"/efi.img /tmp/$efi_tmp_name
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/$iso_mbr_part_type -no-pad -append_partition 2 0xef \/tmp\/$efi_tmp_name/" \
    -e "s/--efi-boot efi\.img/-eltorito-alt-boot -e --interval:appended_partition_2:all:: -no-emul-boot/" \
    -e "s/--protective-msdos-label/$protective/" \
     )

elif test x"$mode" = xmbr_hfs_copy
then
  # Exchange arguments for MBR and HFS+ layout
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/$iso_mbr_part_type -no-pad -append_partition 2 0xef \/tmp\/$(basename "$dir")\/efi.img/" \
    -e "s/--protective-msdos-label/$protective/" \
     )

elif test x"$mode" = xgpt_appended
then
  # Exchange arguments for no-HFS MBR-only layout
  efi_tmp_name=grub-mkrescue-sed-efi-img.$$
  mv "$dir"/efi.img /tmp/$efi_tmp_name
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/-no-pad -append_partition 2 0xef \/tmp\/$efi_tmp_name -appended_part_as_gpt -partition_offset 16/" \
    -e "s/--efi-boot efi\.img/-eltorito-alt-boot -e --interval:appended_partition_2:all:: -no-emul-boot/" \
    -e "s/-hfsplus .*CoreServices\/boot.efi//" \
     )

elif test x"$mode" = xgpt_appended_copy
then
  # Exchange arguments for no-HFS MBR-only layout
  x=$(echo " $*" | sed \
    -e "s/-efi-boot-part --efi-boot-image/-no-pad -append_partition 2 0xef \/tmp\/$(basename "$dir")\/efi.img -appended_part_as_gpt -partition_offset 16/" \
    -e "s/-hfsplus .*CoreServices\/boot.efi//" \
     )

elif test x"$mode" = xoriginal
then
  # Pass arguments unchanged
  x=" $*"

else
  echo >&2
  echo "$0 : FATAL : Unknown manipulation mode '$mode'." >&2
  echo >&2
  exit 1
fi

if test x"$debug" = xyes -o x"$debug" = xextra
then
  echo "+ converted xorriso arguments:" >&2
  echo "  $x" >&2
  echo >&2
fi

# Run xorriso binary with the converted arguments
use_gdb=no
if test "$use_gdb" = yes
then
  gdb_file=/tmp/grub-mkrescue-sed-gdb
  echo b assess_appended_gpt >$gdb_file
  echo run $MKRESCUE_SED_XORRISO_ARGS $x >>$gdb_file
  gdb -x $gdb_file "$xorriso"
  ret=0
else
  "$xorriso" $MKRESCUE_SED_XORRISO_ARGS $x
  ret=$?
fi

# Move back the ESP if it was separated
if test -n "$efi_tmp_name" -a -e /tmp/$efi_tmp_name
then
   mv /tmp/$efi_tmp_name "$dir"/efi.img
fi

exit $ret

