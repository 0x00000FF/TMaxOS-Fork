SUBDIRS = src themes images scripts systemd-units

if BUILD_DOCUMENTATION
SUBDIRS += docs
endif

DISTCHECK_CONFIGURE_FLAGS = --disable-tests --disable-systemd-integration

EXTRA_DIST = ChangeLog                                                         \
             README

MAINTAINERCLEANFILES = aclocal.m4                                              \
                       config.h.in                                             \
                       config.h.in~                                            \
                       config.sub                                              \
                       configure                                               \
                       Makefile.in
