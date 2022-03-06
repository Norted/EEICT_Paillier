CC = /usr/bin/cc

CFLAGS		= -Iheaders -Wall -g -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer 
CLIBFLAGS	= -Iheaders -std=c99 -pedantic -Wall -Wextra -g -fPIC
INCLUDE		= -I/usr/local/include -I/usr/local/include/openssl -I/usr/local/lib
LIBFLAGS	= -lm -lssl -lcrypto -lcjson -lpthread

SOURCES		= $(wildcard ./src/*.c)
HEADERS		= $(wildcard ./headers/*.h)

OBJS = $(SOURCES: .c=.o)

all: clean main

main: $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) $(INCLUDE) main.c -o $@ $(LIBFLAGS)


.PHONY: clean

clean:
	rm -f main
	rm -rf *.o
	rm -f *.json
	rm -f ./keys/*.json
	rm -f ./precomputed_values/*.json
	rm -f ./results/*.csv