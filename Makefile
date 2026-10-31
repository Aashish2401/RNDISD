CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
PKG     := pkg-config libusb-1.0
LABEL   := com.local.rndisd
PLIST   := /Library/LaunchDaemons/$(LABEL).plist

rndisd: rndisd.c
	$(CC) $(CFLAGS) $(shell $(PKG) --cflags) -o $@ $< $(shell $(PKG) --libs) -lpthread

install: rndisd
	install -d /usr/local/bin
	install -m 755 rndisd /usr/local/bin/rndisd
	install -m 644 -o root -g wheel $(LABEL).plist $(PLIST)
	-xattr -c $(PLIST) /usr/local/bin/rndisd
	-launchctl bootout system/$(LABEL)
	launchctl bootstrap system $(PLIST)
	@echo "Installed. Logs: tail -f /var/log/rndisd.log"

uninstall:
	-launchctl bootout system/$(LABEL)
	rm -f $(PLIST) /usr/local/bin/rndisd
	-ifconfig feth40 destroy
	-ifconfig feth41 destroy

clean:
	rm -f rndisd
