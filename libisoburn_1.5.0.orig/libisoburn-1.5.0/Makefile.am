
# ts A90315 : LIBBURNIA_PKGCONFDIR is defined OS specific in acinclude.m4
# was: pkgconfigdir=$(libdir)/pkgconfig
pkgconfigdir=$(LIBBURNIA_PKGCONFDIR)

libincludedir=$(includedir)/libisoburn

lib_LTLIBRARIES = libisoburn/libisoburn.la 
ACLOCAL_AMFLAGS = -I ./

## ========================================================================= ##

# Build libraries
libisoburn_libisoburn_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) $(LIBLDFLAGS)
libisoburn_libisoburn_la_SOURCES = \
	libisoburn/isoburn.h \
	libisoburn/libisoburn.h \
	libisoburn/burn_wrap.c \
	libisoburn/data_source.c \
	libisoburn/isoburn.c \
	libisoburn/isofs_wrap.c \
\
	xorriso/xorriso.h \
	xorriso/xorriso_private.h \
	xorriso/sfile.h \
	xorriso/sfile.c \
	xorriso/aux_objects.h \
	xorriso/aux_objects.c \
	xorriso/findjob.h \
	xorriso/findjob.c \
	xorriso/check_media.h \
	xorriso/check_media.c \
	xorriso/misc_funct.h \
	xorriso/misc_funct.c \
	xorriso/text_io.h \
	xorriso/text_io.c \
	xorriso/match.h \
	xorriso/match.c \
	xorriso/emulators.h \
	xorriso/emulators.c \
	xorriso/disk_ops.h \
	xorriso/disk_ops.c \
	xorriso/cmp_update.h \
	xorriso/cmp_update.c \
	xorriso/parse_exec.h \
	xorriso/parse_exec.c \
	xorriso/opts_a_c.c \
	xorriso/opts_d_h.c \
	xorriso/opts_i_o.c \
	xorriso/opts_p_z.c \
\
	xorriso/xorrisoburn.h \
	xorriso/base_obj.h \
	xorriso/base_obj.c \
	xorriso/lib_mgt.h \
	xorriso/lib_mgt.c \
	xorriso/sort_cmp.h \
	xorriso/sort_cmp.c \
	xorriso/drive_mgt.h \
	xorriso/drive_mgt.c \
	xorriso/iso_img.h \
	xorriso/iso_img.c \
	xorriso/iso_tree.h \
	xorriso/iso_tree.c \
	xorriso/iso_manip.h \
	xorriso/iso_manip.c \
	xorriso/write_run.h \
	xorriso/write_run.c \
	xorriso/read_run.h \
	xorriso/read_run.c \
	xorriso/filters.h \
	xorriso/filters.c \
	xorriso/xorriso_timestamp.h \
	xorriso/xorriso_buildstamp.h

libisoburn_libisoburn_la_LIBADD = \
	$(THREAD_LIBS) \
	-lisofs \
	-lburn

libinclude_HEADERS = \
	libisoburn/libisoburn.h \
	xorriso/xorriso.h

# libisoburn_libisoburn_la_CFLAGS = $(READLINE_DEF) $(LIBACL_DEF) $(XATTR_DEF) \
#                         $(EXTF_DEF) $(EXTF_SUID_DEF) $(ZLIB_DEF) \
#                         $(XORRISO_DVD_OBS_64K)

## ========================================================================= ##


# This is the reference application of libisoburn. See man xorriso/xorriso.1
# 
bin_PROGRAMS = \
	xorriso/xorriso

# This looks quite ugly with make install: xorriso.c is compiled twice again
#
# Trying to create a build timestamp file
#
# BUILT_SOURCES = xorriso/xorriso_buildstamp.h
#
# phony targets get rebuilt every time
#
# .PHONY: xorriso/xorriso_buildstamp.h
# xorriso/xorriso_buildstamp.h:
# 	date -u '+#define Xorriso_build_timestamP "%Y.%m.%d.%H%M%S"' >xorriso/xorriso_buildstamp.h
# 	cat xorriso/xorriso_buildstamp.h

xorriso_xorriso_CPPFLAGS = -Ilibisoburn
# xorriso_xorriso_CFLAGS = $(READLINE_DEF) $(LIBACL_DEF) $(XATTR_DEF) \
#                          $(EXTF_DEF) $(EXTF_SUID_DEF) $(ZLIB_DEF) \
#                          $(XORRISO_DVD_OBS_64K)

xorriso_xorriso_LDADD = libisoburn/libisoburn.la -lisofs -lburn \
		$(THREAD_LIBS) $(LIBBURN_ARCH_LIBS)

xorriso_xorriso_SOURCES = \
	xorriso/xorriso.h \
	xorriso/xorriso_main.c


# Install symbolic links to the xorriso binary
#
install-exec-hook:
	if test -e "$(DESTDIR)$(bindir)"/xorrisofs ; then rm "$(DESTDIR)$(bindir)"/xorrisofs ; else echo ; fi
	ln -s xorriso "$(DESTDIR)$(bindir)"/xorrisofs
	if test -e "$(DESTDIR)$(bindir)"/osirrox ; then rm "$(DESTDIR)$(bindir)"/osirrox ; else echo ; fi
	ln -s xorriso "$(DESTDIR)$(bindir)"/osirrox
	if test -e "$(DESTDIR)$(bindir)"/xorrecord ; then rm "$(DESTDIR)$(bindir)"/xorrecord ; else echo ; fi
	ln -s xorriso "$(DESTDIR)$(bindir)"/xorrecord
	$(LIBBURNIA_LDCONFIG_CMD) "$(DESTDIR)$(libdir)" || echo 'NOTE: Explicit dynamic library configuration failed. If needed, configure manually for:' "$(DESTDIR)$(libdir)"


# Alternative to the disabled .PHONY above.
# Trying to create a build timestamp file semi-manually:  make buildstamped
#
buildstamp:
	date -u '+#define Xorriso_build_timestamP "%Y.%m.%d.%H%M%S"' >xorriso/xorriso_buildstamp.h
	cat xorriso/xorriso_buildstamp.h

# For now   make buildstamped  has to be performed explicitly.
buildstamped: buildstamp
	make


# "make clean" shall remove a few stubborn .libs directories
# which George Danchev reported Dec 03 2011.
# Learned from: http://www.gnu.org/software/automake/manual/automake.html#Clean
clean-local:
	-rm -rf test/.libs

# Will be executed by "make check"
check-local:
	xorriso/xorriso -no_rc -version -list_extras all

## Build companion applications
noinst_PROGRAMS = \
	test/compare_file \
	xorriso/make_xorriso_1

# A program to compare two files in mirrored trees in mounted filesystems
# To compare tree /media/dvd and /original/dir :
#   find /media/dvd -exec test/compare_file '{}' /media/dvd /original/dir ';'
#
test_compare_file_CPPFLAGS =
test_compare_file_CFLAGS =
test_compare_file_LDADD =
test_compare_file_SOURCES = test/compare_file.c

# Specialized converter from xorriso/xorriso.texi to xorriso/xorriso.1
#
xorriso_make_xorriso_1_CPPFLAGS =
xorriso_make_xorriso_1_CFLAGS =
xorriso_make_xorriso_1_LDADD =
xorriso_make_xorriso_1_SOURCES = xorriso/make_xorriso_1.c

# A Proof-of-concept for frontends
bin_SCRIPTS = \
	frontend/xorriso-tcltk


## ========================================================================= ##

## Build documentation (You need Doxygen for this to work)
webhost = http://libburn-api.pykix.org
webpath = /
docdir = $(DESTDIR)$(prefix)/share/doc/$(PACKAGE)-$(VERSION)

doc:	doc/html

doc/html: doc/doxygen.conf
	if [ -f ./doc/doc.lock ]; then \
		$(RM) -r doc/html; \
		doxygen doc/doxygen.conf; \
	fi

doc-upload: doc/html
	scp -r $</* $(webhost):$(webpath)

## Not by default any more.
## It is unclear who is supposed to create file ./doc/doc.lock
# all: doc

install-data-local: 
	if [ -f ./doc/doc.lock ]; then \
		$(mkinstalldirs) $(docdir)/html; \
		$(INSTALL_DATA) doc/html/* $(docdir)/html; \
	fi

uninstall-local:
	rm -rf $(docdir)

## ========================================================================= ##

# Indent source files
indent_files = \
	$(libisoburn_libisoburn_la_SOURCES)
	

indent: $(indent_files)
	indent -bad -bap -nbbb -nbbo -nbc -bli0 -br -bls   \
		-cdw -ce -cli0 -ncs -nbfda -i8 -l79 -lc79   \
		-lp -saf -sai -nprs -npsl -saw -sob -ss -ut \
		-sbi0 -nsc -ts8 -npcs -ncdb -fca            \
		$^

.PHONY: indent

## ========================================================================= ##

# Extra things
nodist_pkgconfig_DATA = \
	libisoburn-1.pc

man_MANS = \
	xorriso/xorriso.1 \
	xorriso/xorrisofs.1 \
	xorriso/xorrecord.1 \
	xorriso/xorriso-tcltk.1

info_TEXINFOS = \
	xorriso/xorriso.texi \
	xorriso/xorrisofs.texi \
	xorriso/xorrecord.texi \
	xorriso/xorriso-tcltk.texi

# To have a file in releng_generated_data. If the directory itself is listed
# in Makefile.am EXTRA_DIST, then its .svn subdir gets into the tarball.
releng/releng_generated_data/placeholder:
	touch releng/releng_generated_data/placeholder

EXTRA_DIST = \
	bootstrap \
	libisoburn-1.pc.in \
	version.h.in \
	doc/comments \
	doc/doxygen.conf.in \
	doc/partition_offset.wiki \
	doc/qemu_xorriso.wiki \
	doc/startup_file.txt \
	frontend/frontend_pipes_xorriso.c \
	frontend/README-tcltk \
	frontend/xorriso-tcltk \
	frontend/sh_on_named_pipes.sh \
	frontend/xorriso_broker.sh \
	frontend/grub-mkrescue-sed.sh \
	README \
	AUTHORS \
	CONTRIBUTORS \
	COPYRIGHT \
	COPYING \
	INSTALL \
	ChangeLog \
	libisoburn/libisoburn.ver \
	xorriso/changelog.txt \
	xorriso/xorriso_buildstamp_none.h \
	xorriso/README_gnu_xorriso \
	xorriso/make_docs.sh \
	releng/README \
	releng/auto_cxx \
	releng/auto_isocontent \
	releng/auto_printsize \
	releng/change_shell_to_use \
	releng/codesamples/api_3lib.cpp \
	releng/codesamples/api_xorriso.cpp \
	releng/inc/releng_getopts.inc \
	releng/jigdo-gen-md5-list \
	releng/jigdo-gen-md5-list.1 \
	releng/manual_burn \
	releng/manual_devices \
	releng/manual_isojigdo \
	releng/releng_generated_data/placeholder \
	releng/run_all_auto \
	releng/template_new \
	$(man_MANS)


