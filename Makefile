TARGETS=flagmon

CD=cd
CP=cp
TAR=tar
GPG=gpg
MAKE=make
RM=rm
SUDO=sudo

CC=gcc
# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DFINDIF=$(FINDIF) -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -DFREEBSD=$(FREEBSD) -DMACOSX=$(MACOSX) -I/usr/include/pcap -L/opt/csw/lib -R/opt/csw/lib

CFLAGS2=-g -I/usr/local/include -I/usr/include/pcap
LDFLAGS2=-g -L/usr/local/lib -L/opt/csw/lib

all: flagmon

doc: arping.yodl
	yodl2man -o arping.8 arping.yodl

install:
	install -c flagmon /usr/local/bin/flagmon
	install flagmon.8 /usr/local/man/man8/flagmon.8

SYS=$(shell uname -s)
ifeq ($(SYS),SunOS)
EXTRA_LIBS=-lsocket -lnsl
endif

flagmon: flagmon.c hexdump.c
	$(CC) $(CFLAGS2) $(LDFLAGS2) -o flagmon flagmon.c -lpcap -lrt -lpcre $(EXTRA_LIBS)

clean:
	rm -f *.o $(TARGETS)

distclean: clean
	rm -f config{.cache,.h,.log,.status}

V=$(shell grep version arping-2/arping.c|grep const|sed 's:[a-z =]*::;s:f;::')
DFILE=arping-$(V).tar.gz
DDIR=arping-$(V)
dist:
	($(CD) ..; \
	$(CP) -ax arping $(DDIR); \
	$(RM) -fr $(DDIR)/{.\#*,CVS,.svn,*~} \
		$(DDIR)/arping-2/{.\#*,CVS,.svn,*~}; \
	$(MAKE) -C $(DDIR) doc; \
	$(TAR) cfz $(DFILE) $(DDIR); \
	$(GPG) -b -a $(DFILE); \
	)

maintainerclean: distclean
	rm -f config{.h.in,ure}
