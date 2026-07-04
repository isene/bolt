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

.PHONY: all install install-greeter uninstall clean logo

all: bolt bolt-auth bolt-greet

bolt: bolt.asm
	$(NASM) -f elf64 bolt.asm -o bolt.o
	$(LD) bolt.o -o bolt
	rm -f bolt.o

bolt-greet: bolt-greet.asm greetfont.inc
	$(NASM) -f elf64 bolt-greet.asm -o bolt-greet.o
	$(LD) bolt-greet.o -o bolt-greet
	rm -f bolt-greet.o

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

# Greeter: bolt-greet (session chooser on DRM) + greet-session (launcher) +
# systemd unit. Installing does NOT enable it — test by hand from a VT first
# (sudo systemctl stop gdm3; sudo bolt-greet-run), then:
#   sudo systemctl disable gdm3 && sudo systemctl enable bolt-greet
install-greeter: bolt-greet
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 bolt-greet $(DESTDIR)$(BINDIR)/bolt-greet
	install -m 0755 greet-session $(DESTDIR)$(BINDIR)/greet-session
	install -m 0755 bolt-greet-run $(DESTDIR)$(BINDIR)/bolt-greet-run
	install -m 0644 bolt-greet.service /etc/systemd/system/bolt-greet.service
	@echo
	@echo "  Greeter installed (NOT enabled). Hand-test from a VT:"
	@echo "      sudo systemctl stop gdm3 && sudo bolt-greet-run"
	@echo "  Make it the boot greeter:"
	@echo "      sudo systemctl disable gdm3 && sudo systemctl enable bolt-greet"
	@echo "      sudo loginctl enable-linger geir   # user bus before first login"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/bolt $(DESTDIR)$(BINDIR)/bolt-auth
	rm -f $(DESTDIR)$(BINDIR)/bolt-greet $(DESTDIR)$(BINDIR)/greet-session
	rm -f $(DESTDIR)$(BINDIR)/bolt-greet-run /etc/systemd/system/bolt-greet.service

clean:
	rm -f bolt bolt.o bolt-auth bolt-greet bolt-greet.o
