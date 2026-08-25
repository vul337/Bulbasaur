ifeq "" "$(LLVM_CONFIG)"
  LLVM_CONFIG=llvm-config
endif

ifeq "$(shell uname -s)" "Darwin"
  # On some odd MacOS system configurations, the Xcode sdk path is not set correctly
  SDK_LD = -L$(shell xcrun --show-sdk-path)/usr/lib
  LDFLAGS += $(SDK_LD)
endif

ifeq "" "$(LLVM_CONFIG)"
  LLVM_CONFIG := llvm-config
endif
LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
ifneq "" "$(LLVM_BINDIR)"
  ifeq "$(shell test -x $(LLVM_BINDIR)/clang && echo 1)" "1"
    CC := $(LLVM_BINDIR)/clang
  endif
endif

CFLAGS := -O3 -funroll-loops -g -fPIC

all:	libAFLDriver.a

aflpp_driver.o:	aflpp_driver.c
	-$(CC) -I. -I../include $(CFLAGS) -c aflpp_driver.c

libAFLDriver.a:	aflpp_driver.o
	@ar rc libAFLDriver.a aflpp_driver.o
	@cp -vf libAFLDriver.a ../

clean:
	rm -f *.o libAFLDriver*.a libAFLQemuDriver.a aflpp_qemu_driver_hook.so *~ core aflpp_driver_test
