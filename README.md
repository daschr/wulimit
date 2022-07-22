# wulimit
ulimit for Windows.

## Building
* install the mingw32 compiler (x86_64-w64-mingw32-gcc) and make
* `make`

## Usage
* `./wulimit.exe -v 1000` - limits the virtual memory of for each process (and future children) of the session to `1GB`
* `./wulimit.exe -v 1000 -V 4000` - limits the virtual memory of for each process (and future children) of the session to `1GB` and the total sum of all processes to `4GB`

## Testing
* `./forkbomb.exe` - should not freeze your system when wulimit is used :wink:
