CC = gcc
CFLAGS = -g -W -Wall -I../include -lpthread
EXEC = disturber
SRC = $(wildcard *.c)
OBJ = log.o communication.o device.o packets.o disturber.o victims.c

all: $(EXEC)

disturber: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean mrproper
clean:
	rm -rf *.o
	rm -rf *.pcap
	find . -type f -perm +x -exec rm {} \;
