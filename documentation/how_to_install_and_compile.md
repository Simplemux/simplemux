How to install ROHC and compile Simplemux
-----------------------------------------

This implementation includes these RoHC modes:
- RoHC unidirectional.
- RoHC bidirectional optimistic
- RoHC bidirectional reliable is not yet implemented.

RoHC cannot be enabled in one of the peers and disabled in the other peer.

RoHC is able to compress the next kinds of traffic flows:
- IP/UDP/RTP: If the UDP packets have the destination ports `1234`, `36780`, `33238`, `5020`, `5002`, the compressor assumes that they are RTP.
- IP/UDP
- IP/TCP
- IP/ESP
- IP/UDP-Lite

## Required packages

In Debian, you will need these packages:
```
sudo apt-get install git
sudo apt-get install build-essential
sudo apt-get install pkgconf
```

Download version 1.7.0 from https://rohc-lib.org/support/download/, and unzip the content in a folder. You can do it with these commands:
```
$ wget https://rohc-lib.org/download/rohc-1.7.x/1.7.0/rohc-1.7.0.tar.xz --no-check-certificate
$ tar -xvf rohc-1.7.0.tar.xz
```

Go go the ROHC folder and make:
```
$ cd rohc-1.7.0/
$ ./configure --prefix=/usr
$ make all
$ make check
$ sudo make install
$ cd ..
```

And now, you can clone Simplemux:
```
$ git clone https://github.com/Simplemux/simplemux.git
```

Set the value of the compiler options in `commonFunctions.h`. You can define the next three values, in order to make Simplemux faster:
```
#define DEBUG 1   // if you comment this line, debug info is not allowed
#define LOGFILE 1 // if you comment this line, logs are not allowed
#define ASSERT 1  // if you comment this line, assertions are not allowed
```

And now, you can compile and build Simplemux

## Using gcc

```
$ cd simplemux/src
$ gcc -o simplemux -g -Wall -Wextra $(pkg-config rohc --cflags)  buildMuxedPacket.c packetsToSend.c netToTun.c tunToNet.c periodExpired.c help.c socketRequest.c init.c simplemux.c commonfunctions.c tunToNetUtilities.c netToTunUtilities.c $(pkg-config rohc --libs )
```

## Using cmake

```
$ cd src
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
```
Note: the last line can be substituted by `make`.