CC=x86_64-w64-mingw32-gcc


all:
	$(CC) -O3 -Wall -pedantic -Werror -o wulimit src/wulimit.c -lpsapi
	$(CC) -O3 -Wall -pedantic -Werror -o forkbomb src/forkbomb.c

debug:
	$(CC) -O3 -Wall -pedantic -Werror -o wulimit -DDEBUG src/wulimit.c -lpsapi
	$(CC) -O3 -Wall -pedantic -Werror -o forkbomb -DDEBUG src/forkbomb.c

clean:
	rm wulimit.exe forkbomb.exe
