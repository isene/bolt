# bolt — pure-asm screen locker for CHasm.
#
# Two artefacts:
#   bolt        x86_64 NASM, no libc, owns the X session and the UI.
#   bolt-auth   tiny C helper, suid root, runs crypt() against shadow.
#
# Logo is pre-baked from chasm.svg into raw RGBA so the asm side has
# zero image-decoding code. Re-run `make logo` after editing the SVG.

NASM     ?= nasm
LD       ?= ld
CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra
LDLIBS   ?= -lcrypt

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

LOGO_SRC ?= ../chasm/img/chasm.svg
LOGO_PX  ?= 280

.PHONY: all install uninstall clean logo

all: bolt bolt-auth

bolt: bolt.asm
	$(NASM) -f elf64 bolt.asm -o bolt.o
	$(LD) bolt.o -o bolt
	rm -f bolt.o

bolt-auth: bolt-auth.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Pre-bake the CHasm logo to a raw RGBA blob the asm side can mmap and
# blit straight into an XImage. Done at build time so users don't need
# rsvg-convert on the install machine.
#
# Output: img/logo.rgba — 4 bytes per pixel (R,G,B,A), row-major,
# top-left origin. img/logo.dim — two ASCII decimals "WIDTH HEIGHT\n".
logo: img/logo.rgba

img/logo.rgba: $(LOGO_SRC)
	@command -v convert >/dev/null || { echo "need ImageMagick convert"; exit 1; }
	convert -background none -resize $(LOGO_PX)x$(LOGO_PX) $(LOGO_SRC) -depth 8 RGBA:img/logo.rgba
	printf '%s %s\n' $(LOGO_PX) $(LOGO_PX) > img/logo.dim

install: bolt bolt-auth
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 bolt $(DESTDIR)$(BINDIR)/bolt
	install -m 4755 -o root -g root bolt-auth $(DESTDIR)$(BINDIR)/bolt-auth
	@echo
	@echo "  bolt installed. The auth helper is suid root (mode 4755):"
	@ls -la $(DESTDIR)$(BINDIR)/bolt-auth
	@echo
	@echo "  Trigger from tile by adding to ~/.tilerc:"
	@echo "      bind Mod4+Ctrl+l exec $(BINDIR)/bolt"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/bolt $(DESTDIR)$(BINDIR)/bolt-auth

clean:
	rm -f bolt bolt.o bolt-auth
