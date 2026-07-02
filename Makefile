# PSP homebrew build uses psptoolchain (psp-gcc). Host tests need only gcc.
PSPSDK_PATH := $(shell psp-config --pspsdk-path 2>/dev/null)

HOST_CC ?= gcc
HOST_CFLAGS = -O0 -g -Wall -Wextra -I. -I./hmac-sha1/src
HOST_TEST_SRCS = tests/test_totp.c totp_core.c base32/base32.c \
	hmac-sha1/src/hmac/hmac_sha1.c hmac-sha1/src/sha/sha1.c
HOST_TEST_BIN = tests/test_totp

.PHONY: host-test

host-test:
	$(HOST_CC) $(HOST_CFLAGS) -o $(HOST_TEST_BIN) $(HOST_TEST_SRCS)
	./$(HOST_TEST_BIN)

ifeq ($(PSPSDK_PATH),)

.DEFAULT_GOAL := host-test
.PHONY: all
all: host-test
	@echo "psp-config not found; ran host tests only."
	@echo "Install https://github.com/pspdev/pspdev for EBOOT.PBP"

else

.DEFAULT_GOAL := all

TARGET = totp_4_psp
OBJS = main.o totp_core.o ./hmac-sha1/src/hmac/hmac_sha1.o ./hmac-sha1/src/sha/sha1.o ./base32/base32.o ./common/callback.o \
		./intrafont031g/libccc.o ./intrafont031g/intraFont.o \
		./intrafont031g/libraries/graphics.o ./intrafont031g/libraries/framebuffer.o

INCDIR = ./hmac-sha1/src
CFLAGS = -O0 -g -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

LIBDIR =
LIBS = -lpspgum -lpspgu -lpng -lz -lm
LDFLAGS =

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = TOTP 4 PSP

PSPSDK=$(PSPSDK_PATH)
include $(PSPSDK)/lib/build.mak

endif
