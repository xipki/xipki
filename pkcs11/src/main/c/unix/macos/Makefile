CC = clang

SRC_DIR = ../../common/src
INC_DIR = ../../common/include
OS_SRC_DIR = ../src

# we do not need '-fpack-struct' as option to get byte aligned structure
# members as required by PKCS#11,
# all PKCS#11 modules seem to be compiled without this option

CFLAGS = -dynamiclib -O2 -fPIC -Wall -DUNIX \
         -I$(INC_DIR) -I$(SRC_DIR) -I$(OS_SRC_DIR)

SRCS = $(OS_SRC_DIR)/platform.c $(wildcard $(SRC_DIR)/*.c)

TARGETS = release

VPATH = $(SRC_DIR) $(INC_DIR)

all: $(TARGETS)

release: amd64release arm64release
	mkdir -p universal/
	lipo -create amd64/libpkcs11wrapper.jnilib \
	  arm64/libpkcs11wrapper.jnilib \
	  -output universal/libpkcs11wrapper.jnilib

amd64release:
	mkdir -p amd64/
	$(CC) $(CFLAGS) -target x86_64-apple-macos10.12 \
	  $(SRCS) -o amd64/libpkcs11wrapper.jnilib

arm64release:
	mkdir -p arm64
	$(CC) $(CFLAGS) -target arm64-apple-macos11 \
	  $(SRCS) -o arm64/libpkcs11wrapper.jnilib

clean:
	rm -rf amd64 arm64 universal
