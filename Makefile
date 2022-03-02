CC = /usr/bin/cc

CFLAGS		= -Iheaders -Wall -g -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer 
CLIBFLAGS	= -Iheaders -std=c99 -pedantic -Wall -Wextra -g -fPIC
INCLUDE		= -I/usr/local/include -I/usr/local/include/openssl -I/usr/local/lib -I./jsmn
LIBFLAGS	= -lm -lssl -lcrypto -lcjson

SOURCES = 	$(wildcard ./src/*.c)
HEADERS = 	$(wildcard ./headers/*.h)

OBJS = $(SOURCES: .c=.o)

all: clean main

main: $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) $(INCLUDE) main.c -o $@ $(LIBFLAGS)


.PHONY: clean

clean:
	rm -f main
	rm -rf *.o