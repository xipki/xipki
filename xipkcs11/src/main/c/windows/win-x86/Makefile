#CC = i686-w64-mingw32.static-gcc
#CC = i686-w64-mingw32.shared-gcc
CC = gcc

SRC_DIR = ../../common/src
INC_DIR = ../../common/include
OS_SRC_DIR = ../src

REL_DIR = release/
TARGETS = release

# we do not need '-fpack-struct' as option to get byte aligned structure
# members as required by PKCS#11,
# all PKCS#11 modules seem to be compiled without this option
# added -Wl,--add-stdcall-alias for 32 bit windows
# (https://www3.ntu.edu.sg/home/ehchua/programming/java/JavaNativeInterface.html)

CFLAGS = -O2 -fPIC -Wall -std=c11 -shared -Wl,--add-stdcall-alias -m32 \
         -I$(INC_DIR) -I$(SRC_DIR) -I$(OS_SRC_DIR)

SRCS = $(OS_SRC_DIR)/platform.c $(wildcard $(SRC_DIR)/*.c)

all : $(TARGETS)

VPATH = $(SRC_DIR) $(INC_DIR)

.PHONY	: release
release :
	mkdir -p $(REL_DIR)
	$(CC) $(CFLAGS) -o $(REL_DIR)pkcs11wrapper.dll $(SRCS)

clean :
	rm -rf $(REL_DIR)*
