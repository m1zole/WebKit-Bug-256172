CC = clang
ARCHFLAGS = -arch x86_64
.PHONY: all
all: stage2.bin 
stage2.bin: stage2.m
	$(CC) $(ARCHFLAGS) -Wall -Wno-error=incompatible-function-pointer-types -o stage2.bin $(LIB) stage2.m -framework Foundation -framework CoreServices -framework Cocoa
