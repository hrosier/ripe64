GCC=gcc
CLG=clang
# Disable stack protection, make the stack executable and add debug info
CFLAGS=-fno-stack-protector -z execstack -g

all: build/gcc_attack_gen build/clang_attack_gen

build/gcc_attack_gen: ./source/attack_gen.c
	${GCC} ${CFLAGS} ./source/attack_gen.c -o ./build/gcc_attack_gen

build/clang_attack_gen: ./source/attack_gen.c
	${CLG} ${CFLAGS} ./source/attack_gen.c -o ./build/clang_attack_gen

clean:
	rm ./build/*
