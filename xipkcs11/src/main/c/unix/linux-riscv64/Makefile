CC = gcc

SRC_DIR = ../../common/src
INC_DIR = ../../common/include
OS_SRC_DIR = ../src

REL_DIR = release/
TARGETS = release

# we do not need '-fpack-struct' as option to get byte aligned structure
# members as required by PKCS#11,
# all PKCS#11 modules seem to be compiled without this option

CFLAGS = -O2 -shared -fPIC -DUNIX -Wall -std=c11 \
         -I$(INC_DIR) -I$(SRC_DIR) -I$(OS_SRC_DIR)

SRCS = $(OS_SRC_DIR)/platform.c $(wildcard $(SRC_DIR)/*.c)

all : $(TARGETS)

VPATH = $(SRC_DIR) $(INC_DIR)

.PHONY	: release
release :
	mkdir -p $(REL_DIR)
	$(CC) $(CFLAGS) -o $(REL_DIR)libpkcs11wrapper.so $(SRCS)

clean :
	rm -rf $(REL_DIR)*
