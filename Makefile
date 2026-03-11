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

# Source files - modular architecture
SRC      := main.c \
            common.c \
            audio/audio_buffer.c \
            audio/audio_analysis.c \
            audio/capture.c \
            audio/capture_pcap.c \
            audio/capture_alsa.c \
            audio/capture_afxdp.c \
            shazam/shazam.c \
            shazam/id_thread.c \
            writer/async_writer.c \
            writer/writer_thread.c \
            server/sse_server.c \
            db/database.c

# Pro DJ Link CDJ integration (optional, enabled with --prolink-interface)
PROLINK_SRC := prolink/prolink_thread.c \
               prolink/cdj_types.c \
               prolink/prolink.c \
               prolink/registration.c \
               prolink/packet_handler.c \
               prolink/dbserver.c \
               prolink/nfs_client.c \
               prolink/pdb_parser.c \
               prolink/track_cache.c

SRC      += $(PROLINK_SRC)
OBJ      := $(SRC:.c=.o)

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

CC       ?= gcc
CSTD     ?= -std=c11
WARN     ?= -Wall -Wextra -Werror=return-type -Wno-missing-field-initializers
OPT      ?= -O2 -pipe
THREAD   ?= -pthread

# Feature test macros - needed for BSD types (pcap) and GNU extensions (strcasestr)
FEATURE_MACROS := -D_DEFAULT_SOURCE -D_GNU_SOURCE

# Try to pick up system cflags/libs via pkg-config when available
ALSA_CFLAGS  := $(shell pkg-config --cflags alsa 2>/dev/null)
ALSA_LIBS    := $(shell pkg-config --libs alsa 2>/dev/null)
ifdef ALSA_LIBS
  ALSA_CFLAGS += -DHAVE_ALSA
endif
CURL_CFLAGS  := $(shell pkg-config --cflags libcurl 2>/dev/null)
CURL_LIBS    := $(shell pkg-config --libs libcurl 2>/dev/null)

# pcap support (optional with AF_XDP, disable with DISABLE_PCAP=1)
ifndef DISABLE_PCAP
PCAP_CFLAGS  := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS    := $(shell pkg-config --libs libpcap 2>/dev/null)
ifeq ($(PCAP_LIBS),)
  PCAP_LIBS := -lpcap
endif
PCAP_CFLAGS += -DHAVE_PCAP
endif

SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null)
ifeq ($(SQLITE_LIBS),)
  SQLITE_LIBS := -lsqlite3
endif

# FLAC encoding support (optional)
FLAC_CFLAGS  := $(shell pkg-config --cflags flac 2>/dev/null)
FLAC_LIBS    := $(shell pkg-config --libs flac 2>/dev/null)
ifneq ($(FLAC_LIBS),)
  FLAC_CFLAGS += -DHAVE_FLAC
endif

# AF_XDP support (optional, requires libbpf + libxdp)
# Enable with: make ENABLE_AF_XDP=1
ifdef ENABLE_AF_XDP
  LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
  LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null)
  LIBXDP_CFLAGS := $(shell pkg-config --cflags libxdp 2>/dev/null)
  LIBXDP_LIBS   := $(shell pkg-config --libs libxdp 2>/dev/null)
  ifneq ($(LIBBPF_LIBS),)
    ifneq ($(LIBXDP_LIBS),)
      AF_XDP_CFLAGS := $(LIBBPF_CFLAGS) $(LIBXDP_CFLAGS) -DHAVE_AF_XDP
      AF_XDP_LIBS   := $(LIBBPF_LIBS) $(LIBXDP_LIBS)
    else
      $(warning libxdp not found, AF_XDP support disabled)
    endif
  else
    $(warning libbpf not found, AF_XDP support disabled)
  endif
endif

# Vibra library detection
# Override with: make VIBRA_PREFIX=/path/to/vibra
VIBRA_PREFIX ?= $(shell \
  for p in /usr/local /opt/homebrew /usr; do \
    if [ -f "$$p/lib/libvibra.dylib" ] || [ -f "$$p/lib/libvibra.so" ]; then \
      echo "$$p"; break; \
    fi; \
  done)

ifneq ($(VIBRA_PREFIX),)
  VIBRA_LIBS   := -L$(VIBRA_PREFIX)/lib -lvibra -lstdc++
  VIBRA_CFLAGS := -DHAVE_VIBRA -I$(VIBRA_PREFIX)/include
else
  $(warning libvibra not found, audio fingerprinting (--audio-tag) disabled)
  VIBRA_LIBS   :=
  VIBRA_CFLAGS :=
endif

MATH_LIBS   ?= -lm

# Build flags - use := to override any environment LDFLAGS
CFLAGS   := $(CSTD) $(OPT) $(WARN) $(THREAD) $(FEATURE_MACROS) $(ALSA_CFLAGS) $(CURL_CFLAGS) $(PCAP_CFLAGS) $(SQLITE_CFLAGS) $(FLAC_CFLAGS) $(AF_XDP_CFLAGS) $(VIBRA_CFLAGS)
LDFLAGS  := $(THREAD) $(ALSA_LIBS) $(CURL_LIBS) $(PCAP_LIBS) $(SQLITE_LIBS) $(FLAC_LIBS) $(AF_XDP_LIBS) $(MATH_LIBS) $(VIBRA_LIBS) -Wl,-rpath,/usr/local/lib

# Extra flags opt-in
CFLAGS   += $(CFLAGS_EXTRA)
LDFLAGS  += $(LDFLAGS_EXTRA)

all: $(APP)

debug: CFLAGS := -std=c11 -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined $(WARN) $(THREAD) $(FEATURE_MACROS) $(ALSA_CFLAGS) $(CURL_CFLAGS) $(PCAP_CFLAGS) $(SQLITE_CFLAGS) $(FLAC_CFLAGS) $(AF_XDP_CFLAGS) $(VIBRA_CFLAGS) $(CFLAGS_EXTRA)
debug: LDFLAGS := $(THREAD) $(ALSA_LIBS) $(CURL_LIBS) $(PCAP_LIBS) $(SQLITE_LIBS) $(FLAC_LIBS) $(AF_XDP_LIBS) $(MATH_LIBS) $(VIBRA_LIBS) -Wl,-rpath,/usr/local/lib -fsanitize=address,undefined $(LDFLAGS_EXTRA)
debug: clean $(APP)

$(APP): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

# Subdirectory compilation rules
audio/%.o: audio/%.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

shazam/%.o: shazam/%.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

writer/%.o: writer/%.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

server/%.o: server/%.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

db/%.o: db/%.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

prolink/%.o: prolink/%.c
	$(CC) $(CFLAGS) -I. -c $< -o $@

# BPF program compilation (requires clang and libbpf headers)
# BPF_CFLAGS can be used for cross-compilation (e.g., -nostdinc -isystem /path/to/sysroot/include)
ifdef ENABLE_AF_XDP
BPF_OBJ := audio/slink_xdp.bpf.o prolink/prolink_xdp.bpf.o
CLANG  ?= clang
BPFTOOL ?= bpftool
BPF_CFLAGS ?=

audio/slink_xdp.bpf.o: audio/slink_xdp.bpf.c
	$(CLANG) -O2 -g -target bpf $(BPF_CFLAGS) -c $< -o $@

prolink/prolink_xdp.bpf.o: prolink/prolink_xdp.bpf.c
	$(CLANG) -O2 -g -target bpf $(BPF_CFLAGS) -c $< -o $@

bpf: $(BPF_OBJ)

$(APP): $(OBJ) $(BPF_OBJ)
endif

install: $(APP)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(APP) "$(DESTDIR)$(BINDIR)/$(APP)"
ifdef ENABLE_AF_XDP
	install -d "$(DESTDIR)$(PREFIX)/share/clubtagger"
	install -m 0644 audio/slink_xdp.bpf.o "$(DESTDIR)$(PREFIX)/share/clubtagger/"
	install -m 0644 prolink/prolink_xdp.bpf.o "$(DESTDIR)$(PREFIX)/share/clubtagger/"
endif

clean:
	$(RM) $(OBJ) $(APP) *.o audio/*.o shazam/*.o writer/*.o server/*.o db/*.o prolink/*.o

.PHONY: all debug clean install bpf
