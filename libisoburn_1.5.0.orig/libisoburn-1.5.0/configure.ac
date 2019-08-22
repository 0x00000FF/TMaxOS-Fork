AC_INIT([libisoburn], [1.5.0], [http://libburnia-project.org])
AC_PREREQ([2.50])
dnl AC_CONFIG_HEADER([config.h])	

AC_CANONICAL_HOST
AC_CANONICAL_TARGET

LIBBURNIA_SET_FLAGS

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([./])

dnl Hint: Search list for version code aspects:
dnl       /AC_INIT(
dnl       /ISOBURN_.*_VERSION
dnl       /LT_.*
dnl       /LIB.*_REQUIRED

dnl The API version codes are defined in libisoburn/libisoburn.h
dnl #define  isoburn_header_version_*
dnl configure.ac only rules the libtool revision numbering about
dnl LT_CURREN, LT_AGE, LT_REVISION where SONAME becomes LT_CURRENT - LT_AGE
dnl 
dnl These three are only copies to provide libtool with unused LT_RELEASE
ISOBURN_MAJOR_VERSION=1
ISOBURN_MINOR_VERSION=5
ISOBURN_MICRO_VERSION=0

dnl ISOBURN_VERSION=$ISOBURN_MAJOR_VERSION.$ISOBURN_MINOR_VERSION.$ISOBURN_MICRO_VERSION
 
AC_SUBST(ISOBURN_MAJOR_VERSION)
AC_SUBST(ISOBURN_MINOR_VERSION)
AC_SUBST(ISOBURN_MICRO_VERSION)
dnl AC_SUBST(ISOBURN_VERSION)

dnl Libtool versioning
dnl Generate libisoburn.so.1.x.y
dnl SONAME will become LT_CURRENT - LT_AGE
dnl 
dnl ts B80915
dnl This is the release version 1.5.0 = libisoburn.so.1.107.0
dnl ### This is the development version after above stable release
dnl LT_CURRENT++, LT_AGE++ have not happened yet.
dnl ### LT_CURRENT++, LT_AGE++ has happened meanwhile.
dnl
dnl SONAME = 108 - 107 = 1 . Library name = libisoburn.so.1.107.0
LT_RELEASE=$ISOBURN_MAJOR_VERSION.$ISOBURN_MINOR_VERSION
LT_CURRENT=108
LT_AGE=107
LT_REVISION=0
LT_CURRENT_MINUS_AGE=`expr $LT_CURRENT - $LT_AGE`

AC_SUBST(LT_RELEASE)
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)
AC_SUBST(LT_CURRENT_MINUS_AGE)

AC_PREFIX_DEFAULT([/usr/local])
test "$prefix" = "NONE" && prefix=$ac_default_prefix

AM_MAINTAINER_MODE

AM_PROG_CC_C_O
AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN

dnl Large file support
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO
AC_CHECK_FUNC([fseeko])
if test ! $ac_cv_func_fseeko; then
   AC_ERROR([Libburn requires largefile support.])
fi

if test x$LIBISOBURN_OLD_ICONV_CONFIGURE = x
then

dnl ts B00410 : To detect the need for -liconv and const argument of iconv()
    LIBBURNIA_CHECK_ICONV

else

dnl Outdated: produces double -liconv and warnings about parameter mismatch
dnl If iconv(3) is in an extra lib, then it gets added to variable LIBS.
dnl If not, then no -liconv will be added.
    AC_CHECK_LIB(iconv, iconv, , )
dnl GNU iconv has no function iconv() but libiconv() and a macro iconv()
    AC_CHECK_LIB(iconv, libiconv, , )

fi

AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
# LIBTOOL="$LIBTOOL --silent"

AC_PROG_INSTALL

AC_CHECK_HEADERS()

dnl Check for tm_gmtoff field in struct tm
AC_CHECK_MEMBER([struct tm.tm_gmtoff],
	[AC_DEFINE(HAVE_TM_GMTOFF, 1,
		[Define this if tm structure includes a tm_gmtoff entry.])],
	,
	[#include <time.h>])

dnl Whether timezone is an integer variable
AH_TEMPLATE([Libburnia_timezonE], [Either timezone or 0])
LIBBURNIA_TRY_TIMEZONE
if test x$LIBBURNIA_TIMEZONE = xtimezone
then
   AC_DEFINE([Libburnia_timezonE], [timezone])
else
   AC_DEFINE([Libburnia_timezonE], [0])
fi

THREAD_LIBS=-lpthread
AC_SUBST(THREAD_LIBS)

TARGET_SHIZZLE
AC_SUBST(ARCH)
AC_SUBST(LIBBURNIA_PKGCONFDIR)
AC_SUBST(LIBBURN_ARCH_LIBS)

# Do not link libcam or libvolmgt if not available.
# (They are indirect dependency on FreeBSD or Solaris.)
LIBBURNIA_CHECK_ARCH_LIBS(optional)

dnl Determine target directory for libisoburn-*.pc
dnl Important: Must be performed _after_ TARGET_SHIZZLE
dnl
LIBBURNIA_SET_PKGCONFIG

AC_ARG_ENABLE(libreadline,
[  --enable-libreadline    Enable use of libreadline by xorriso, default=yes],
               , enable_libreadline=yes)
if test x$enable_libreadline = xyes; then
dnl Check whether there is readline-devel and readline-runtime.
dnl If not, erase this macro which would enable use of readline(),add_history()
    READLINE_DEF="-DXorriso_with_readlinE"

    if test x$XORRISO_OLD_READLINE_CONFIGURE = x
    then

dnl ts B00411 : To disable readline if not all needed functions are present
        LIBBURNIA_ASSERT_READLINE

    else
dnl The empty yes case obviously causes -lreadline to be linked
        AC_CHECK_HEADER(readline/readline.h, AC_CHECK_LIB(readline, readline, , READLINE_DEF= ), READLINE_DEF= )
dnl The X= in the yes case prevents that -lreadline gets linked twice
        AC_CHECK_HEADER(readline/history.h, AC_CHECK_LIB(readline, add_history, X= , READLINE_DEF= ), READLINE_DEF= )
    fi
else
    READLINE_DEF=
    echo "disabled libreadline"
fi
if test x$READLINE_DEF = x; then
    if test x$enable_libreadline = xyes; then
        libedit_deflt=yes
    else
        libedit_deflt=no
    fi
    AC_ARG_ENABLE(libedit,
[  --enable-libedit        Enable use of libedit by xorriso if not libreadline,
                          default= setting of --enable-libreadline],
                   , enable_libedit=$libedit_deflt)
    if test x$enable_libedit = xyes; then
        READLINE_DEF="-DXorriso_with_editlinE"

        LIBBURNIA_ASSERT_EDITLINE

    else
        READLINE_DEF=
        echo "disabled libedit"
    fi
fi
AC_SUBST(READLINE_DEF)


dnl ts A90329
dnl ACL and xattr do not need to be enabled in libisoburn or xorriso source
dnl but without AC_CHECK_LIB() xorriso will not be linked with -lacl .
dnl On my Linux this does work with an ACL enabled libisofs but in general
dnl it seems not be right.
dnl So for now it seems to be best to do the same configuration for libisoburn
dnl and xorriso as for libisofs.
AC_ARG_ENABLE(libacl,
[  --enable-libacl         Enable use of libacl by libisofs, default=yes],
               , enable_libacl=yes)
LIBACL_DEF=
if test x$LIBBURNIA_SUPP_ACL = xlibacl
then
    if test x$enable_libacl = xyes; then
dnl Check whether there is libacl-devel and libacl-runtime.
dnl If not, erase this macro which would enable use of acl_to_text and others
        LIBACL_DEF="-DLibisofs_with_aaip_acL"
dnl The empty yes case obviously causes -lacl to be linked
        has_acl_h_but_no_func=0
        AC_CHECK_HEADER(sys/acl.h, AC_CHECK_LIB(acl, acl_to_text, , has_acl_h_but_no_libacl=1 ), LIBACL_DEF= )
        if test "$has_acl_h_but_no_libacl" = 1
        then
            AC_CHECK_LIB(c, acl_to_text, X= , LIBACL_DEF= )
        fi
    fi
fi
if test x$LIBACL_DEF = x-DLibisofs_with_aaip_acL
then
    if test x$has_acl_h_but_no_libacl = x1
    then
        echo "enabled  local processing of ACL"
    else
        echo "enabled  libacl, local processing of ACL"
    fi
else
    echo "disabled local processing of ACL"
fi
AC_SUBST(LIBACL_DEF)


AC_ARG_ENABLE(xattr,
              [  --enable-xattr          Enable use of extended file attributes by libisofs, default=yes],
              , enable_xattr=yes)
XATTR_DEF=
if test x"$LIBBURNIA_SUPP_FATTR" = xxattr
then
    if test "x$enable_xattr" = xyes; then
dnl Check whether there is the header for Linux xattr.
dnl If not, erase this macro which would enable use of listxattr and others
        XATTR_DEF="-DLibisofs_with_aaip_xattR"
        AC_CHECK_HEADER(attr/xattr.h, AC_CHECK_LIB(c, listxattr, X= ,
                                                   XATTR_DEF= ), XATTR_DEF= )
    fi
elif test x"$LIBBURNIA_SUPP_FATTR" = xextattr
then
    if test "x$enable_xattr" = xyes; then
        XATTR_DEF="-DLibisofs_with_freebsd_extattR"
        AC_CHECK_HEADER(sys/extattr.h, AC_CHECK_LIB(c, extattr_list_file, X=,
                                                    XATTR_DEF= ), XATTR_DEF= )
    fi
fi
if test x$XATTR_DEF = x-DLibisofs_with_aaip_xattR
then
    echo "enabled  xattr, local processing of extended file attributes Linux style"
elif test x$XATTR_DEF = x-DLibisofs_with_freebsd_extattR
then
    echo "enabled  extattr, local processing of extended file attributes FreeBSD style"
else
    echo "disabled local processing of extended file attributes"
fi
AC_SUBST(XATTR_DEF)


dnl ts A90409
dnl Same situation as with xattr and ACL: libisoburn does not depend directly
dnl on zlib. But if it is enabled in libisofs then it seems wise to link it
dnl with libisoburn apps.
AC_ARG_ENABLE(zlib,
[  --enable-zlib           Enable use of zlib by libisofs, default=yes],
               , enable_zlib=yes)
if test x$enable_zlib = xyes; then
dnl Check whether there is the header for zlib. 
dnl If not, erase this macro which would enable use of compress2() and others.
dnl Linking fails on SuSE 9.0 because zlib has compress2() but lacks  
dnl compressBound(). So compressBound is the more modern thing to test.
dnl The empty parameter after "compressBound" causes -lz.
    ZLIB_DEF="-DLibisofs_with_zliB"
    AC_CHECK_HEADER(zlib.h, AC_CHECK_LIB(z, compressBound, , ZLIB_DEF= ), ZLIB_DEF= )
else
    ZLIB_DEF=
fi
AC_SUBST(ZLIB_DEF)

dnl ts B00928
AC_ARG_ENABLE(libjte,
[  --enable-libjte         Enable use of libjte by xorriso, default=yes],
               , enable_libjte=yes)
if test "x$enable_libjte" = xyes; then
    LIBJTE_DEF="-DXorriso_with_libjtE"
    AC_CHECK_HEADER(libjte/libjte.h, AC_CHECK_LIB(jte, libjte_new, , LIBJTE_DEF= ), LIBJTE_DEF= )
else
    LIBJTE_DEF=
fi
AC_SUBST(LIBJTE_DEF)

dnl ts B00107
dnl Just for the case that it is necessary to give link option -lcdio not only
dnl with libburn but also with libburn apps like xorriso.
dnl On SuSE 10.2 this is not needed. libburn finds libcdio on its own.
case $host_os in
    cygwin*|mingw*)
        default_libcdio=yes
        ;;
    *)
        default_libcdio=no
        ;;
esac
AC_ARG_ENABLE(libcdio,
[  --enable-libcdio        Enable use of libcdio as system adapter, default=no (except on MSWindows)],
               , enable_libcdio=$default_libcdio)
if test x$enable_libcdio = xyes; then
dnl Check whether there is libcdio-devel and libcdio-runtime.
dnl If not, erase this macro
    LIBCDIO_DEF="-DLibburn_use_libcdiO"
dnl The empty yes case obviously causes -lcdio to be linked
    AC_CHECK_HEADER(cdio/cdio.h, AC_CHECK_LIB(cdio, mmc_last_cmd_sense, , LIBCDIO_DEF= ), LIBCDIO_DEF= )
else
    LIBCDIO_DEF=
fi
if test x$LIBCDIO_DEF = x
then
    if test x$enable_libcdio = xyes
    then
      echo "WARNING: could not enable use of libcdio as system adapter"
    fi
else
    echo "enabled  use of libcdio as system adapter"
fi
AC_SUBST(LIBCDIO_DEF)


AC_ARG_ENABLE(external-filters,
[  --enable-external-filters       Enable use of external filter programs by xorriso, default=yes],
               , enable_external_filters=yes)
if test x"$enable_external_filters" = xyes; then
    EXTF_DEF="-DXorriso_allow_external_filterS"
    echo "enabled  xorriso external filter programs"
else
    EXTF_DEF=
    echo "disabled xorriso external filter programs"
fi
AC_SUBST(EXTF_DEF)

AC_ARG_ENABLE(external-filters-setuid,
[  --enable-external-filters-setuid   Enable xorriso external filter programs under setuid, default=no],
               , enable_external_filters_setuid=no)
if test x$enable_external_filters_setuid = xyes; then
    EXTF_SUID_DEF="-DXorriso_allow_extf_suiD"
    echo "enabled  xorriso external filter programs under setuid"
else
    EXTF_SUID_DEF=
    echo "disabled xorriso external filter programs under setuid"
fi
AC_SUBST(EXTF_SUID_DEF)


AC_ARG_ENABLE(launch-frontend,
[  --enable-launch-frontend        Enable start of piped frontend program by xorriso, default=yes],
               , enable_launch_frontend=yes)
if test x"$enable_launch_frontend" = xyes; then
    LFRONT_DEF="-DXorriso_allow_launch_frontenD"
    echo "enabled  xorriso command -launch_frontend"
else
    LFRONT_DEF=
    echo "disabled xorriso command -launch_frontend"
fi
AC_SUBST(LFRONT_DEF)

AC_ARG_ENABLE(launch-frontend-setuid,
[  --enable-launch-frontend-setuid   Enable start of piped frontend program under setuid, default=no],
               , enable_launch_frontend_setuid=no)
if test x$enable_launch_frontend_setuid = xyes; then
    LFRONT_SUID_DEF="-DXorriso_allow_extf_suiD"
    echo "enabled  xorriso command -launch_frontend under setuid"
else
    LFRONT_SUID_DEF=
    echo "disabled xorriso command -launch_frontend under setuid"
fi
AC_SUBST(LFRONT_SUID_DEF)


AC_ARG_ENABLE(dvd-obs-64k,
[  --enable-dvd-obs-64k            64 KB default size for xorriso DVD writing, default=no],
               , enable_dvd_obs_64=no)
if test x$enable_dvd_obs_64k = xyes; then
    XORRISO_DVD_OBS_64K="-DXorriso_dvd_obs_default_64K"
    echo "enabled  xorriso write size default 64 KB on DVD"
else
    XORRISO_DVD_OBS_64K=
    echo "disabled xorriso write size default 64 KB on DVD"
fi
AC_SUBST(XORRISO_DVD_OBS_64K)

# Library versioning normally serves a complex purpose.
# Since libisoburn obeys strict ABI backward compatibility, it needs only the
# simple feature to declare function names "global:" or "local:". Only the
# global ones are visible to applications at library load time.
AC_ARG_ENABLE(versioned-libs,
[  --enable-versioned-libs         Enable strict symbol encapsulation , default=yes],
               , enable_versioned_libs=yes)
if test x$enable_versioned_libs = xyes; then
    vers_libs_test=no
    LIBISOBURN_ASSERT_VERS_LIBS
    if test x$vers_libs_test = xno
    then
        echo "disabled strict symbol encapsulation (test failed)"
    else
        echo "enabled  strict symbol encapsulation"
    fi
else
    echo "disabled strict symbol encapsulation"
fi

AC_ARG_ENABLE(ldconfig-at-install,
[  --enable-ldconfig-at-install    On GNU/Linux run ldconfig, default=yes],
               , ldconfig_at_install=yes)
if test x$ldconfig_at_install = xyes; then
    dummy=dummy
else
    LIBBURNIA_LDCONFIG_CMD="echo 'NOTE: ldconfig is disabled. If needed, configure manually for:'"
    echo "disabled run of ldconfig during installation on GNU/Linux"
fi
AC_SUBST(LIBBURNIA_LDCONFIG_CMD)


AC_CHECK_HEADER(libburn/libburn.h, LIBBURNIA_HAVE_LIBBURN=1, LIBBURNIA_HAVE_LIBBURN=0)
AC_CHECK_HEADER(libisofs/libisofs.h, LIBBURNIA_HAVE_LIBISOFS=1, LIBBURNIA_HAVE_LIBISOFS=0)
if test x$LIBBURNIA_HAVE_LIBBURN = x0; then
    echo "FATAL: Lacking libburn development header file <libburn/libburn.h>" 2>&1
    echo "HINT: You first have to install libburn before you can build libisoburn" 2>&1
fi
if test x$LIBBURNIA_HAVE_LIBISOFS = x0; then
    echo "FATAL: Lacking libisofs development header file <libisofs/libisofs.h>" 2>&1
    echo "HINT: You first have to install libisofs before you can build libisoburn" 2>&1
fi
if test x$LIBBURNIA_HAVE_LIBBURN = x0 -o x$LIBBURNIA_HAVE_LIBISOFS = x0; then
    echo "ABORT: Lacking mandatory prerequisites" 2>&1
    exit 1
fi

# ------- Visible mark in configure : Start of library check

# Check for proper library versions if this is desired.
# (It fails too often on too many systems.)
AC_ARG_ENABLE(pkg-check-modules,
[  --enable-pkg-check-modules      Enable pkg-config check for libburn and libisofs , default=no],
               , enable_pkg_check_modules=no)
if test x$enable_pkg_check_modules = xyes; then

dnl If PKG_CHECK_MODULES is to be used after this if-block,
dnl then it might be necessary to perform PKG_PROG_PKG_CONFIG before the block.

  LIBBURN_REQUIRED=1.5.0
  LIBISOFS_REQUIRED=1.5.0
  PKG_CHECK_MODULES(LIBBURN, libburn-1 >= $LIBBURN_REQUIRED)
  PKG_CHECK_MODULES(LIBISOFS, libisofs-1 >= $LIBISOFS_REQUIRED)
  if test x$LIBCDIO_DEF = x; then
    dummy=dummy
  else
    LIBCDIO_REQUIRED=0.83
    PKG_CHECK_MODULES(LIBCDIO, libcdio >= $LIBCDIO_REQUIRED)
  fi
else
  echo "checking for LIBBURN... skipped, no --enable-pkg-check-modules"
  echo "checking for LIBISOFS... skipped, no --enable-pkg-check-modules"
  if test x$LIBCDIO_DEF = x; then
    dummy=dummy
  else
    echo "checking for LIBCDIO... skipped, no --enable-pkg-check-modules"
  fi
fi

# ------- Visible mark in configure : End of library check

dnl Add compiler-specific flags

dnl See if the user wants aggressive optimizations of the code
AC_ARG_ENABLE(debug,
[  --enable-debug          Disable aggressive optimizations [default=yes]],
              , enable_debug=yes)
if test x$enable_debug != xyes; then
    if test x$GCC = xyes; then
        CFLAGS="-O3 $CFLAGS"
        CFLAGS="-fexpensive-optimizations $CFLAGS"
    fi
    CFLAGS="-DNDEBUG $CFLAGS"
else
    if test x$GCC = xyes; then
        CFLAGS="-g -pedantic -Wall -Wextra -Wno-unused-parameter -Wno-char-subscripts $CFLAGS"
    fi
    CFLAGS="-DDEBUG $CFLAGS"
fi

CFLAGS="$READLINE_DEF $LIBACL_DEF $XATTR_DEF $EXTF_DEF $EXTF_SUID_DEF $LFRONT_DEF $LFRONT_SUID_DEF $ZLIB_DEF $LIBJTE_DEF $XORRISO_DVD_OBS_64K $CFLAGS"

AC_CONFIG_FILES([
	Makefile
	doc/doxygen.conf
	version.h
	libisoburn-1.pc
	])
AC_OUTPUT
