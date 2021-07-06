VERSION != git describe --tags --abbrev=0
RELEASE != git rev-parse --short HEAD
PREFIX := /usr
GREGGD_ARCHIVE := greggd-$(VERSION)-$(RELEASE).tar.gz

.PHONY: build
build:
	go build -v ./cmd/greggd/

.PHONY: test
test:
	go test -v ./...

.PHONY: install
install: greggd
	mkdir -p $(DESTDIR)/$(PREFIX)/sbin/
	mkdir -p $(DESTDIR)/$(PREFIX)/share/greggd/{c,doc}/
	mkdir -p $(DESTDIR)/$(PREFIX)/lib/systemd/system/
	install -m 0755 ./greggd $(DESTDIR)/$(PREFIX)/sbin/
	install -m 0644 ./README.md $(DESTDIR)/$(PREFIX)/share/greggd/doc/
	install -m 0644 ./LICENSE.md $(DESTDIR)/$(PREFIX)/share/greggd/doc/
	install -m 0644 ./csrc/*.c $(DESTDIR)/$(PREFIX)/share/greggd/c/
	install -m 0644 ./init/greggd.service $(DESTDIR)/$(PREFIX)/lib/systemd/system/

.PHONY: clean
clean:
	rm ./greggd

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)/$(PREFIX)/sbin/greggd
	mkdir -p $(DESTDIR)/$(PREFIX)/share/greggd/{c,doc}/
	mkdir -p $(DESTDIR)/$(PREFIX)/lib/systemd/system/greggd.service

.PHONY: archive
archive:
	git archive -o greggd-$(VERSION)-$(RELEASE).tar.gz HEAD

.PHONY: srpm
srpm:
	make archive
	cp $(GREGGD_ARCHIVE) ~/rpmbuild/SOURCES
	rpmbuild -bs ./build/greggd.spec

.PHONY: rpm
rpm:
	rpmbuild -bb ./build/greggd.spec
