TARGETS=flagmon

SRCS=flagmon.c flagmon.h hexdump.c tcp.c

MAKE=make
CC=gcc

#CFLAGS=-I/usr/local/include -L/usr/local/lib -DFINDIF=$(FINDIF) -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -DFREEBSD=$(FREEBSD) -DMACOSX=$(MACOSX) -I/usr/include/pcap

CFLAGS2=-I/usr/local/include -I/usr/include/pcap
LDFLAGS2=-L/usr/local/lib

all: flagmon

install:
	install -c flagmon /usr/local/bin/flagmon
	install flagmon.8 /usr/local/man/man8/flagmon.8

SYS=$(shell uname -s)
ifeq ($(SYS),SunOS)
EXTRA_LIBS=-lsocket -lnsl
endif

flagmon: $(SRCS)
	$(CC) $(CFLAGS2) $(LDFLAGS2) -o flagmon flagmon.c -lpcap -lpcre $(EXTRA_LIBS)

static: $(SRCS)
	$(CC) $(CFLAGS2) $(LDFLAGS2) -o flagmon-static flagmon.c -lpcap -lpcre -lpthread $(EXTRA_LIBS) -static
	strip flagmon-static

32: $(SRCS)
	$(CC) $(CFLAGS2) $(LDFLAGS2) -m32 -o flagmon32 flagmon.c -lpcap -lpcre $(EXTRA_LIBS)

static32: $(SRCS)
	$(CC) $(CFLAGS2) $(LDFLAGS2) -m32 -o flagmon32-static flagmon.c -lpcap -lpcre -lpthread $(EXTRA_LIBS) -static
	strip flagmon32-static

clean:
	rm -f *.o $(TARGETS)
