DESTDIR=
PREFIX=/usr/local
MANDIR=$(PREFIX)/share/man
TAR=tar
FIND=find
SED=sed

all: manpage

install: all
	mkdir -p $(DESTDIR)$(MANDIR)/man1/
	mkdir -p $(DESTDIR)$(PREFIX)/bin/
	cp convmv.1.gz $(DESTDIR)$(MANDIR)/man1/
	install -m 755 convmv $(DESTDIR)$(PREFIX)/bin/

manpage:
	pod2man --section 1 --center=" " convmv | gzip > convmv.1.gz

clean:
	rm -f convmv.1.gz convmv-*.tar.gz MD5sums SHA256sums .files .name
	rm -rf suite

test:
	test -d suite || $(TAR) xf testsuite.tar
	cd suite ; ./dotests.sh

dist: clean
	$(SED) -n "2,2p" convmv |$(SED) "s/.*convmv \([^ ]*\).*/\1/" > VERSION
	$(FIND) . -name "*" ! -name ".*" -type f -print | xargs sha256sum | gpg --clearsign > .SHA256sums
	mv .SHA256sums SHA256sums
	ls > .files
	echo convmv-`cat VERSION` >.name
	mkdir `cat .name`
	mv `cat .files` `cat .name`
	$(TAR) cvf - * |gzip > `cat .name`.tar.gz
	mv `cat .name`/* .
	rmdir `cat .name`
