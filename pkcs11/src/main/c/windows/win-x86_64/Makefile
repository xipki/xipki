CC = x86_64-w64-mingw32.shared-gcc

SRC_DIR = ../../common/src
INC_DIR = ../../common/include
OS_SRC_DIR = ../src

REL_DIR = release/
TARGETS = release

CFLAGS = -O2 -fPIC -Wall -std=c11 -shared -m64 \
         -I$(INC_DIR) -I$(SRC_DIR) -I$(OS_SRC_DIR)

SRCS = $(OS_SRC_DIR)/platform.c $(wildcard $(SRC_DIR)/*.c)

all : $(TARGETS)

VPATH = $(SRC_DIR) $(INC_DIR)

# we do not need '-fpack-struct' as option to get byte aligned structure
# members as required by PKCS#11,
# all PKCS#11 modules seem to be compiled without this option

.PHONY	: release
release :
	mkdir -p $(REL_DIR)
	$(CC) $(CFLAGS) -o $(REL_DIR)pkcs11wrapper.dll $(SRCS)

clean :
	rm -f $(REL_DIR)*
