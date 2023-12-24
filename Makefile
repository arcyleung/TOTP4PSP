TARGET = totp_4_psp
OBJS = ./hmac-sha1/src/hmac/hmac_sha1.o ./hmac-sha1/src/sha/sha1.o \
		./base32/base32.o ../common/callback.o main.o \
		# ./intrafont031g/libraries/framebuffer.o ./intrafont031g/libraries/graphics.o ./intrafont031g/libccc.o ./intrafont031g/intraFont.o

INCDIR = 
CFLAGS = -O2 -g -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

# CC = psp-g++

LIBDIR = 
LDFLAGS = 
LIBS = -lSDL2 -lSDL2main -lSDL2_ttf -lfreetype -lpng -lbz2 -lGL -lGLU -lglut -lz \
         -lpspvfpu -lpsphprm -lpspsdk -lpspctrl -lpspumd -lpsprtc -lpsppower -lpspgum -lpspgu -lpspaudiolib -lpspaudio -lpsphttp -lpspssl -lpspwlan \
         -lpspnet_adhocmatching -lpspnet_adhoc -lpspnet_adhocctl -lpspvram -lm -lvorbis -lvorbisenc -lvorbisfile -logg -lsmpeg -lstdc++

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = TOTP 4 PSP

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak