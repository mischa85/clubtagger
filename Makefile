# Makefile for clubtagger
# Usage:
#   make            # build optimized binary
#   make debug      # build with -g and sanitizers
#   make clean
#   make install PREFIX=/usr/local
#
# Env overrides:
#   CC=clang CFLAGS_EXTRA="-DUSE_SOMETHING" VIBRA_LIBS="-L/path -lvibra -lstdc++"

APP      := clubtagger
SRC      := clubtagger.c
OBJ      := $(SRC:.c=.o)

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

CC       ?= gcc
CSTD     ?= -std=c11
WARN     ?= -Wall -Wextra -Werror=return-type -Wno-missing-field-initializers
OPT      ?= -O2 -pipe
THREAD   ?= -pthread

# Try to pick up system cflags/libs via pkg-config when available
ALSA_CFLAGS  := $(shell pkg-config --cflags alsa 2>/dev/null)
ALSA_LIBS    := $(shell pkg-config --libs alsa 2>/dev/null)
ifdef ALSA_LIBS
  ALSA_CFLAGS += -DHAVE_ALSA
endif
CURL_CFLAGS  := $(shell pkg-config --cflags libcurl 2>/dev/null)
CURL_LIBS    := $(shell pkg-config --libs libcurl 2>/dev/null)
PCAP_CFLAGS  := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS    := $(shell pkg-config --libs libpcap 2>/dev/null)
ifeq ($(PCAP_LIBS),)
  PCAP_LIBS := -lpcap
endif
SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null)
ifeq ($(SQLITE_LIBS),)
  SQLITE_LIBS := -lsqlite3
endif

# Required libraries; vibra usually doesn't ship a pkg-config file
# You can override VIBRA_LIBS from the environment if needed.
VIBRA_LIBS  ?= -lvibra -lstdc++
MATH_LIBS   ?= -lm

CFLAGS   ?= $(CSTD) $(OPT) $(WARN) $(THREAD) $(ALSA_CFLAGS) $(CURL_CFLAGS) $(PCAP_CFLAGS) $(SQLITE_CFLAGS)
LDFLAGS  ?= $(THREAD) $(ALSA_LIBS) $(CURL_LIBS) $(PCAP_LIBS) $(SQLITE_LIBS) $(MATH_LIBS) $(VIBRA_LIBS) -Wl,-rpath,/usr/local/lib

# Extra flags opt-in
CFLAGS   += $(CFLAGS_EXTRA)
LDFLAGS  += $(LDFLAGS_EXTRA)

all: $(APP)

debug: CFLAGS := -std=c11 -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined $(WARN) $(THREAD) $(ALSA_CFLAGS) $(CURL_CFLAGS) $(PCAP_CFLAGS) $(SQLITE_CFLAGS) $(CFLAGS_EXTRA)
debug: LDFLAGS := $(THREAD) $(ALSA_LIBS) $(CURL_LIBS) $(PCAP_LIBS) $(SQLITE_LIBS) $(MATH_LIBS) $(VIBRA_LIBS) -Wl,-rpath,/usr/local/lib -fsanitize=address,undefined $(LDFLAGS_EXTRA)
debug: clean $(APP)

$(APP): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(APP)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(APP) "$(DESTDIR)$(BINDIR)/$(APP)"

clean:
	$(RM) $(OBJ) $(APP)

.PHONY: all debug clean install
