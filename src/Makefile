CC = gcc
CFLAGS = -g -W -Wall -I../include -lpthread
EXEC = disturber
SRC = $(wildcard *.c)
OBJ = communication.o device.o packets.o disturber.o victims.c

all: $(EXEC)

disturber: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean mrproper
clean:
	rm -rf *.o
	find . -type f -executable -exec rm {} \;
pkgtest:
	$(CC) packets.c -o packets -D __PKG_TEST__
