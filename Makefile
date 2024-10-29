# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is>
# SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com>
# SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com>
# SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com>

VERSION_FILE = version.in.h
GIT_COMMIT_HASH = $(shell git rev-parse --short HEAD)
VERSION_DEFINE = "\#define GIT_COMMIT \"$(GIT_COMMIT_HASH)\""

GLIB_CFLAGS = $(shell pkg-config --cflags --libs glib-2.0)

all: neighsnoopd neighsnoop

neighsnoopd.bpf.c:

neighsnoopd.bpf.o: neighsnoopd.bpf.c neighsnoopd_shared.h
	clang -Wall -O2 -g -target bpf -c neighsnoopd.bpf.c -o neighsnoopd.bpf.o -I/usr/include/x86_64-linux-gnu -I/usr/include/x86_64-linux-gnu/asm -I/usr/include/x86_64-linux-gnu/gnu

neighsnoopd.bpf.skel.h: neighsnoopd.bpf.o
	bpftool gen skeleton neighsnoopd.bpf.o > neighsnoopd.bpf.skel.h

$(VERSION_FILE):
	@echo $(VERSION_DEFINE) > $(VERSION_FILE)

neighsnoopd: neighsnoopd.bpf.skel.h neighsnoopd.c neighsnoopd.h neighsnoopd_shared.h netlink.c cache.c lib.c $(VERSION_FILE)
	gcc -g -Wall -o neighsnoopd -D_GNU_SOURCE -I./include neighsnoopd.c netlink.c cache.c lib.c stats.c logging.c lib/json_writer.c -lbpf -lmnl $(GLIB_CFLAGS)

neighsnoop: neighsnoop.c
	gcc -g -Wall -o neighsnoop neighsnoop.c

clean:
	rm -f neighsnoopd.bpf.o neighsnoopd.bpf.skel.h neighsnoopd neighsnoop cscope.in.out cscope.out cscope.po.out $(VERSION_FILE)

cscope:
	cscope -b -R -q

.PHONY: all cscope clean
