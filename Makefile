TARGET = totp_4_psp
OBJS = main.o ./hmac-sha1/src/hmac/hmac_sha1.o ./hmac-sha1/src/sha/sha1.o ./base32/base32.o ./common/callback.o \
		./intrafont031g/libccc.o ./intrafont031g/intraFont.o \
		./intrafont031g/libraries/graphics.o ./intrafont031g/libraries/framebuffer.o

INCDIR = ../oslibmodv2
CFLAGS = -O0 -g -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

LIBDIR =
LIBS = -lpspgum -lpspgu -lpng -lz -lm
LDFLAGS = 

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = TOTP 4 PSP

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak