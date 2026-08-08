# SPDX-License-Identifier: Apache-2.0
# Builds the local iSecSP authentication server and shared loopback client.
CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g

WARNINGS = -std=c11 -Wall -Wextra -Werror -Wpedantic -Wformat=2 \
	-Wconversion -Wshadow -fno-common -fstack-protector-strong \
	-D_FORTIFY_SOURCE=2

HARDENING_LDFLAGS = -Wl,-z,relro,-z,now

.PHONY: all clean

all: isecsp-auth-server isecsp-auth-client

isecsp-auth-server: server.c ../auth-ipc/protocol.h sdk_abi.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) \
		-Wl,--export-dynamic $(HARDENING_LDFLAGS) -pthread \
		server.c -ldl -o $@

isecsp-auth-client: ../auth-ipc/client.c ../auth-ipc/protocol.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING_LDFLAGS) \
		../auth-ipc/client.c -o $@

clean:
	rm -f isecsp-auth-server isecsp-auth-client