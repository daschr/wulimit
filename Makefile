CC=x86_64-w64-mingw32-gcc

all: wulimit.exe

wulimit.exe:
	$(CC) -Wall -pedantic -Werror -o wulimit wulimit.c

clean: wulimit.exe
	rm wulimit.exe