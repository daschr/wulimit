CC=x86_64-w64-mingw32-gcc


all:
	$(CC) -O3 -Wall -pedantic -Werror -o wulimit wulimit.c -lpsapi
	$(CC) -O3 -Wall -pedantic -Werror -o forkbomb forkbomb.c

clean: wulimit.exe
	rm wulimit.exe
